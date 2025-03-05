#define _POSIX_C_SOURCE 200112L

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "http.h"
#include "ssl_conn.h"
#include "client_side.h"
#include "net.h"
#include "errcode.h"
#include "log.h"
#include "util.h"
extern EVP_PKEY *ca_key;
extern X509 *ca_cert;

extern thread_cond_t *thread_cond;
extern pthread_mutex_t cond_lock;
extern pthread_mutex_t mutex_lock; 
extern pthread_cond_t async_cond;
extern pthread_mutex_t async_mutex;
extern task_arg_t *task_arg;

void log_exit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    
    va_end(ap);
    exit(1);
}

void* xmalloc(size_t sz)
{
    void *p;

    p = malloc(sz);
    if (!p) log_exit("failed to allocate memory");
    return p;
}

// Non-blocking 설정 함수
void set_nonblocking(int fd) 
{
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void set_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    flags &= ~O_NONBLOCK; //논블록 플래그 제거
}

/**
 * @brief 도메인명에서 호스트명 획득하여 remote 서버와 통신을 위한 fd 생성
 * 
 * @param hostname 
 * @param port 
 * @return int file descriptor
 */
int connect_remote_http(const char* hostname, int port)
{
    struct hostent *host;
    if((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    // remote 소켓 연결
    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(remote_fd < 0) {
        log_exit("Remote socket creation failed");
        //perror("Remote socket creation failed");
    }

    struct sockaddr_in remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);
    remoteaddr.sin_port = htons(port);
    connect(remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));
    set_nonblocking(remote_fd);
    return remote_fd;
}

/**
 * @brief remote 서버와 ssl 통신을 위해 SSL 객체 생성
 * 
 * @param remote_fd 
 * @param remote_ctx 
 * @return SSL* 
 */
SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx)
{
    // SSL 연결
    remote_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(remote_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(remote_ctx, TLS1_3_VERSION);
    if (!remote_ctx) {
        perror("Failed to create SSL context for remote server");
        close(remote_fd);
        return NULL;
    }
    SSL *remote_ssl = SSL_new(remote_ctx);
    SSL_set_fd(remote_ssl, remote_fd);

    //connect ssl 
    while(1){
        int ret = SSL_connect(remote_ssl);
        if (ret == 1) {
            LOG(INFO,"Remote[fd: %d] SSL Handshake Success\n",remote_fd);
            return remote_ssl;
        } else {
            int err = SSL_get_error(remote_ssl, ret);
            switch(err) {
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_WANT_WRITE:
                    continue;
                default:
                    LOG(ERROR,"Client SSL Handshake error - %d\n", err);
                    return NULL;
                    // exit(1);
            }
        }
    }

    return remote_ssl;
}

/**
 * @brief tls handshake 요청인지 확인
 * 
 * @param data 
 * @return int 
 * 성공(0), 실패(others)
 */
int is_tls_handshake(const char *data)
{
    //TLS ClientHello 패킷
    //Content Type: Handshake (22,0x16)) - payload 시작 데이터
    //Version: TLS 1.0 (0x0301) - 호환성 보장을 위해 TLS 1.0(0x0301) 또는 SSL 3.0(0x0300) 설정, 실제 사용하는 TLS 버전과 무관
    if (data[0] == 0x16 && data[1] == 0x03 && data[2] >= 0x01) {
        return 1; 
    }
    return 0;
}

int handle_recv_error(int sockfd) 
{
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Non-blocking 모드에서 데이터가 없는 경우
        LOG(INFO,"recv() - No data available, try again later\n");
    } else if (errno == ECONNRESET) {
        // 상대방이 연결을 강제 종료한 경우
        LOG(ERROR,"recv() - Connection reset by peer\n");
        return STAT_FAIL;
        close(sockfd);
    } else if (errno == EINTR) {
        // 인터럽트로 인해 recv()가 중단된 경우, 다시 시도 가능
        LOG(INFO,"recv() - Interrupted by signal, retrying...\n");
    } else {
        // 기타 오류
        LOG(ERROR,"recv() - Error: %s\n", strerror(errno));
        return STAT_FAIL;
        close(sockfd); 
    }
    return STAT_OK;
}

/**
 * @brief 초기 client 요청으로 client, proxy간 프로토콜 확인
 * @details client, proxy간 https 통신을 하는 경우 본 함수에서 proxy 도메인 인증서, 키를 연결한 SSL 객체 셋팅
 * 
 * @param task 
 * @return int 
 * 성공(0), 실패(others)
 */
int initial_read(task_t* task)
{
    ssize_t buf_size = recv(task->client_fd, task->buffer, MAX_BUFFER_SIZE, MSG_PEEK);
    if(buf_size <= 0 )
    {
        if(handle_recv_error(task->client_fd)!=STAT_OK)
        {
            return STAT_FAIL;
        }
        else
             return 1;
        
    }
    
    // if(set_current_time(&task->current_time) == STAT_FAIL)
    // {
    //     return STAT_FAIL;
    // }
    if(is_tls_handshake(task->buffer))
    {
        LOG(DEBUG, "is_tls_handshake");
        //tls_handshake에 이용할 SSL 객체 셋팅
        //TO-DO proxy server ip에 맞게 인증서 생성하는 로직 필요
        task->client_ctx = SSL_CTX_new(TLS_server_method());
        if (!SSL_CTX_use_certificate_file(task->client_ctx, "/home/sgseo/proxyserver/proxy_cert.pem", SSL_FILETYPE_PEM)) {
            perror("Failed to load certificate from file");
            SSL_CTX_free(task->client_ctx);
            // EVP_PKEY_free(key); //sgseo free TO-DO
            // X509_free(dynamic_cert);
            // close(client_sock);
            return STAT_FAIL;
        }

        if (!SSL_CTX_use_PrivateKey_file(task->client_ctx, "/home/sgseo/proxyserver/proxy_key.pem", SSL_FILETYPE_PEM)) {
            perror("Failed to load private key from file");
            SSL_CTX_free(task->client_ctx);
            // EVP_PKEY_free(key);
            // X509_free(dynamic_cert);
            // close(client_sock);
            return STAT_FAIL;
        }
        task->client_ssl = SSL_new(task->client_ctx);
        SSL_set_fd(task->client_ssl, task->client_fd);
        task->state = STATE_CLIENT_PROXY_SSL_CONN;
        task->client_side_https = true;
    }
    else
    {
        task->state = STATE_CLIENT_READ;
    }
    return STAT_OK;
}

int release(task_t* task, int epoll_fd){
    
    return STAT_OK;
}

int recv_data(task_t* task, int epoll_fd)
{
// 클라이언트 데이터 수신
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    
    // client 요청 recv
    while (1) {
        int ret = recv(task->client_fd, task->buffer, MAX_BUFFER_SIZE, 0);
        if (ret > 0) {
            // 데이터 처리
            task->buffer_len = task->buffer_len + ret;
            continue;
        } else if (ret == 0) {
            // 클라이언트 연결 종료
            LOG(ERROR,"Client disconnected\n");
            pthread_mutex_lock(&mutex_lock); 
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
            pthread_mutex_unlock(&mutex_lock); 
            close(task->client_fd);
            close(task->remote_fd);
            free(task);
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 읽을 데이터가 더 이상 없음
                break;
            } else {
                // recv 실패
                perror("recv failed");
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                pthread_mutex_unlock(&mutex_lock); 
                close(task->client_fd);
                free(task);
                exit(1);
            }
        }
    }
    return STAT_OK;

}

int client_auth(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    // 클라이언트 데이터 수신
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    // client 요청 recv
    int ret = recv_data(task, epoll_fd);
    LOG(DEBUG,"Data received from client: %d bytes", task->buffer_len);
    LOG(DEBUG, "recv Data: %s", task->buffer);
    const char *response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy Server\"\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: 80\r\n\r\n<html><body><h1>407 Proxy Authentication Required</h1></body></html>\r\n";
    ret = send(task->client_fd, response, strlen(response), 0);
    LOG(DEBUG, "send result: %d",ret);
    task->state = STATE_CLIENT_READ;
    task->auth = true;
    task->buffer_len = 0;
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    ev->events = EPOLLIN|EPOLLRDHUP ;
    ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);    
    pthread_mutex_unlock(&mutex_lock); 
    return STAT_OK;
}

/**
 * @brief http 프로토콜로 client data read
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_read_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    // if(task->auth==false)
    // {
    //     return client_auth(task, epoll_fd, ev);
    // }

    // 클라이언트 데이터 수신
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    // client 요청 recv
    int ret = recv_data(task, epoll_fd);

    LOG(DEBUG,"Data received from client: %d bytes\n", task->buffer_len);
    LOG(DEBUG,"%.*s\n", task->buffer_len, task->buffer); // 안전하게 출력
    
    // http 요청 로깅

    // http 요청 파싱
    task->req = read_request(task->buffer);
    if(task->req==NULL)
    {
        //error 처리 필요
        return STAT_OK;
    }
    //method CONNECT 일때
    if(!strncmp(task->req->method,"CONNECT", 7)){
        return client_connect_req(task, epoll_fd, ev);
    }
    // url db 조회 -> 필터링 

    if(task->req->port == -1) {
        task->req->port = DEFUALT_HTTP_PORT;
    }
    // remote 연결
    task->remote_fd = connect_remote_http(task->req->host, task->req->port);
    LOG(INFO,"remote connection success\n");
    
    task->state = STATE_REMOTE_WRITE;
    ev->events = EPOLLOUT ;
    ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);
    pthread_mutex_unlock(&mutex_lock); 

    
    // free(req);  
    return STAT_OK;
}

/**
 * @brief https 프로토콜로 client data read
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_read_with_https(task_t* task, int epoll_fd, struct epoll_event *ev)
{

    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    task->buffer_len = 0;
    while(1) { //데이터 전부 읽는 방식 수정 필요
        int ret = SSL_read(task->client_ssl, task->buffer, MAX_BUFFER_SIZE); 
        if (ret > 0) {
            task->buffer_len = task->buffer_len + ret;
            // continue;
            break;
        } else if (ret == 0) {
            LOG(ERROR,"Client disconnected\n");
            pthread_mutex_lock(&mutex_lock); 
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
            pthread_mutex_unlock(&mutex_lock); 
            free_request(task->req);
            SSL_free(task->client_ssl);
            SSL_CTX_free(task->client_ctx);
            close(task->client_fd);
            free(task);
            break;
        } else {
            int err = SSL_get_error(task->client_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // SSL_read finished
                break;
            } else {
                LOG(ERROR,"Client SSL Read error - %d\n", err);
                exit(1);
            }
        }
    }

    LOG(DEBUG,"Data received from client: %d bytes\n", task->buffer_len);
    LOG(DEBUG,"%s\n", task->buffer);

    free_request(task->req);
    task->req = read_request(task->buffer);
    if(task->req){
        if(!strncmp(task->req->method,"CONNECT",7))
        {
            //client <-https-> proxy <-https-> remote인 경우
            //SSL 암호화 연결 상태에서 CONNECT method 처리
            return client_connect_req_with_ssl(task, epoll_fd, ev);
        }

        if(task->req->port == -1) {
            task->req->port = DEFUALT_HTTPS_PORT;
        }
    }
    else{
        task->req = (HTTPRequest*)calloc(1, sizeof(HTTPRequest));
        task->req->port = DEFUALT_HTTPS_PORT;
    }

    task->state = STATE_REMOTE_WRITE;
    ev->events = EPOLLOUT ;
    ev->data.ptr = task;
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);
    pthread_mutex_unlock(&mutex_lock); 

    
    return STAT_OK;
}

/**
 * @brief http 프로토콜로 client data write
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_write_with_https(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    SSL_write(task->client_ssl, task->buffer, task->buffer_len);
    //TO-DO free memory 
    //TO-DO error 처리
    // free_request(task->req);
    // SSL_free(task->client_ssl);
    // SSL_free(task->remote_ssl);
    // SSL_CTX_free(task->client_ctx);
    // SSL_CTX_free(task->remote_ctx);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
    // close(task->remote_fd);
    // close(task->client_fd);
    // free(task);
}

/**
 * @brief https 프로토콜로 client data write
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_write_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    send(task->client_fd, task->buffer, task->buffer_len, 0);
    // 세션 유지시
    // task->state = STATE_CLIENT_READ;
    // ev->events = EPOLLIN|EPOLLRDHUP ;
    // epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
    // free(task->req);

    // TO-DO 세션 종료시 free memory
    // TO-DO error 처리
    // free_request(task->req);
    // SSL_free(task->client_ssl);
    // SSL_free(task->remote_ssl);
    // SSL_CTX_free(task->client_ctx);
    // SSL_CTX_free(task->remote_ctx);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
    // close(task->remote_fd);
    // close(task->client_fd);
    // free(task);
}

/**
 * @brief http 프로토콜로 remote data read
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int remote_read_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
     // 원격 서버 데이터 수신
    // recv 값 유효성 검사해서 유효하지 못한 응답일 경우 소켓 닫는 로직 필요
    
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    task->buffer_len = 0;
    while (1) {
        int ret = recv(task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
        LOG(INFO,"remote read result: %d", ret);
        if (ret > 0) {
            //TO-DO 호출 함수 수정 필요
            int ret2;
            if(task->client_side_https) ret2 = SSL_write(task->client_ssl, task->buffer,ret);
            else ret2 = send(task->client_fd, task->buffer,ret,0);
            task->buffer_len = task->buffer_len + ret;
            continue;
        } else if (ret == 0) {
            // remote 연결 종료
            LOG(DEBUG,"remote disconnected\n");
            if (task->buffer_len == 0) {
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                pthread_mutex_unlock(&mutex_lock); 
                free_request(task->req);
                close(task->client_fd);
                close(task->remote_fd);
                free(task);
                break;
            } else {
                break;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 읽을 데이터가 더 이상 없음 
                // sgseo TO-DO 데이터를 다 읽어서 읽을 데이터가 없는 상황일 수 있는데,, 그럴때는 어떻게 해야되는지 처리 필요
                LOG(DEBUG,"No data to read\n");
                ev->events = EPOLLIN|EPOLLRDHUP ;
                ev->data.ptr = task;
                pthread_mutex_lock(&mutex_lock);
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock);
                break;
            } else {
                // recv 실패
                perror("recv failed");
                pthread_mutex_lock(&mutex_lock);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                pthread_mutex_unlock(&mutex_lock);
                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                close(task->client_fd);
                close(task->remote_fd);
                free(task);
                exit(1);
            }
        }
    }
#if 0 /*remote recv()하고 client send() 반복 하도록 수정*/
    if (task->buffer_len > 0) {
        printf("Data received from remote: %d bytes\n", task->buffer_len);
        printf("%s\n", task->buffer);
        task->state = STATE_CLIENT_WRITE;
        ev->events = EPOLLOUT ;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
    }
#endif
    return STAT_OK;
}

/**
 * @brief https 프로토콜로 remote data read
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int remote_read_with_https(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    //SSL_read()
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    task->buffer_len = 0;
    LOG(DEBUG, "sgseo");
    while(1) {
        //에러 처리 필요
        memset(task->buffer, 0, MAX_BUFFER_SIZE);
        int ret = SSL_read(task->remote_ssl, task->buffer, MAX_BUFFER_SIZE);
        // int ret2 = SSL_write(task->client_ssl, task->buffer, ret);
        //printf("asda\n");
        LOG(DEBUG, "SSL_read result: %d", ret);
        if (ret > 0) {
            //TO-DO 호출 함수 수정 필요
            int ret2;
            if(task->client_side_https) ret2 = SSL_write(task->client_ssl, task->buffer,ret);
            else ret2 = send(task->client_fd, task->buffer,ret,0);
            task->buffer_len = task->buffer_len + ret;
            LOG(DEBUG, "total read bytes: %d", task->buffer_len);
            continue;
        } else if (ret == 0) {
            LOG(DEBUG,"remote disconnected\n");
            if (task->buffer_len == 0) {
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                pthread_mutex_unlock(&mutex_lock); 
                free_request(task->req);
                SSL_free(task->client_ssl);
                SSL_CTX_free(task->client_ctx);
                SSL_free(task->remote_ssl);
                SSL_CTX_free(task->remote_ctx);
                close(task->client_fd);
                close(task->remote_fd);
                free(task);
                break;
            } else {
                break;
            }
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if(err == SSL_ERROR_WANT_READ) LOG(DEBUG, "SSL_read result: SSL_ERROR_WANT_READ");
            else if(err == SSL_ERROR_WANT_WRITE) LOG(DEBUG, "SSL_read result: SSL_ERROR_WANT_WRITE");
            else LOG(ERROR, "SSL_read error %d",err);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                LOG(DEBUG,"No data to read\n");
                ev->events = EPOLLIN|EPOLLRDHUP ;
                ev->data.ptr = task;
                pthread_mutex_lock(&mutex_lock);
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock);
                // // SSL_read finished
                return STAT_FAIL;
                // break;
                // continue;
            } else {
                LOG(ERROR,"Remote SSL Read error - %d\n", err);
                // exit(1);
                break;
            }
        }
    } //데이터 읽을게 더 있으면 

    // 위 반복문 탈출 이후 buffer_len > 0 이면 완료
    // 아닌 경우 remote에서 응답이 아직 안온 상태에서 SSL_read 하였으므로, 다시 이벤트를 기다림

#if 0  /*remote recv()하고 client send() 반복 하도록 수정*/
    if (task->buffer_len > 0) {
        printf("net.c 626 Data received from remote: %d bytes\n", task->buffer_len);
        printf("%s\n", task->buffer);

        task->state = STATE_CLIENT_WRITE;
        ev->events = EPOLLOUT ;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
    }
#endif
    LOG(DEBUG, "sgseo");
    pthread_mutex_lock(&mutex_lock);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
    pthread_mutex_unlock(&mutex_lock);
    LOG(DEBUG, "sgseo");
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
    // close(task->client_fd);
    LOG(DEBUG, "sgseo");
    close(task->remote_fd);
    LOG(DEBUG, "sgseo");
    return STAT_OK;
}

/**
 * @brief http 프로토콜로 remote data write
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 */
int remote_write_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    // 원격 서버로 데이터 송신
    ssize_t sent_bytes = 0;

    
    while (task->buffer_len > 0) {
        ssize_t ret = send(task->remote_fd, task->buffer + sent_bytes, task->buffer_len, 0);
        if (ret > 0) {
            sent_bytes += ret;
            task->buffer_len -= ret;

            // 모든 데이터를 전송 완료한 경우
            if (task->buffer_len == 0) {
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN|EPOLLRDHUP ;
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock); 
                break;
            }
        } else if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (errno == EAGAIN || EWOULDBLOCK ) {
                LOG(DEBUG,"Send buffer full, waiting for EPOLLOUT event...\n");
                ev->events = EPOLLOUT ;
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock); 
                break;
            } else if (errno == EPIPE) {
                LOG(ERROR,"Broken pipe: Connection closed by peer.\n");
                exit(1);
            } else {
                perror("send failed");
                exit(1);
            }
        } else {
            // send 실패 처리
            perror("send failed");
            exit(1);
        }
    }
    
}

/**
 * @brief https 프로토콜로 remote data write
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 */
int remote_write_with_https(task_t* task, int epoll_fd, struct epoll_event *ev)
{ 
    ssize_t sent_bytes = 0;
    while (task->buffer_len > 0) {
        int ret = SSL_write(task->remote_ssl, task->buffer + sent_bytes, task->buffer_len);
        LOG(INFO, "remote_write data: %s", task->buffer + sent_bytes);
        if (ret > 0) {
            sent_bytes += ret;
            task->buffer_len -= ret;

            // 모든 데이터를 전송 완료한 경우
            if (task->buffer_len == 0) {
                LOG(INFO,"Success STATE_REMOTE_WRITE");
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN|EPOLLRDHUP ;
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock); 
                memset(task->buffer, 0 , MAX_BUFFER_SIZE);
                break;
            }
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                LOG(DEBUG,"Send buffer full, waiting for EPOLLOUT event...\n");
                ev->events = EPOLLOUT ;
                pthread_mutex_lock(&mutex_lock); 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                pthread_mutex_unlock(&mutex_lock); 
                break; 
            } else {
                // SSL_write 실패 처리
                LOG(ERROR,"Remote SSL Write error: %d\n", err);
                exit(1);
            }
        }
    }
}

/**
 * @brief client, proxy간 tls handshake 수행
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_proxy_ssl_conn(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    // while(1)
    // {
        
        int ret = SSL_accept(task->client_ssl);
        if (ret == 1) {
            LOG(DEBUG,"Client SSL Handshake Success\n");
            task->state = STATE_CLIENT_READ;
            task->client_side_https = true;
            ev->events = EPOLLIN|EPOLLRDHUP ;
            ev->data.ptr = task;
            // set_nonblocking(task->client_fd);
            pthread_mutex_lock(&mutex_lock); 
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
            pthread_mutex_unlock(&mutex_lock); 
            return STAT_OK;
        }
        // SSL_accept가 완료되지 않은 경우
        int err = SSL_get_error(task->client_ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
                LOG(DEBUG, "SSL_ERROR_WANT_READ");
            case SSL_ERROR_WANT_WRITE:
                LOG(DEBUG, "SSL_ERROR_WANT_WRITE");
            default:
                LOG(DEBUG,"Client SSL Handshake error(%d) - %s\n", err,strerror(err));
                // exit(1);
        }
    // }
    return STAT_OK;
}

/**
 * @brief client connect 요청 응답 및 remote 서버 ssl 연결
 * @details client가 요청하는 remote 서버에 대한 ssl 인증서 생성
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_connect_req(task_t* task, int epoll_fd, struct epoll_event *ev)
{ 
    // url db 조회 -> 필터링 

    // CONNECT => ssl connect => GET or POST 요청 recv
    task->remote_fd = connect_remote_http(task->req->host, task->req->port);
    // remote ssl 연결
    task->remote_ssl = connect_remote_https(task->remote_fd, task->remote_ctx);
    if(task->remote_ssl==NULL)
    {
        // TO-DO 메모리 해제
        pthread_mutex_lock(&mutex_lock); 
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
        pthread_mutex_unlock(&mutex_lock); 
        return STAT_FAIL;
    }
    task->client_side_https = true;
    task->remote_side_https = true;
    // if(task->req->port == -1) {
    //     task->req->port = DEFUALT_HTTPS_PORT;
    // }
    LOG(DEBUG,"Host: %s\n", task->req->host); // 호스트 이름 출력
    LOG(DEBUG,"Port: %d\n", task->req->port); // 포트 출력
    LOG(DEBUG,"CONNECT request for %s:%d\n", task->req->host, task->req->port);
#if 0 /*TO-DO 인증 방식 추가*/
    // client HTTP/1.1 RFC 7235 (Authentication) 
    const char *response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy Server\"\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: 80\r\n\r\n<html><body><h1>407 Proxy Authentication Required</h1></body></html>\r\n";
    int ret = send(task->client_fd, response, strlen(response), 0);
    LOG(DEBUG, "send result: %d",ret);
    
#else
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(task->client_fd, response, strlen(response), 0);
#endif
    if(setup_ssl_cert(task->req->host, ca_key, ca_cert, &task->client_ctx, &task->client_ssl)){
        exit(1);
    }
    // set_blocking(task->client_fd);
    SSL_set_fd(task->client_ssl, task->client_fd);
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
    ev->events = EPOLLIN|EPOLLRDHUP | EPOLLOUT;
    ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->client_fd, ev);
    pthread_mutex_unlock(&mutex_lock); 
    return STAT_OK;
}



/**
 * @brief 앞서 연결한 SSL 통신 위에서 CONNECT method 처리
 * 
 * @details 먼저 recv 버퍼에 CONNECT method 존재 유무 확인
 * CONNECT method가 아닌 경우 client<-https->proxy<-http->remote 통신
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_connect_req_with_ssl(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    task->before_client_ctx = task->client_ctx;
    task->before_client_ssl = task->client_ssl;
    task->client_ctx = NULL;
    task->client_ssl = NULL;
    // // http 요청 로깅

    // // http 요청 파싱
    // task->req = read_request(task->buffer);
    
    // url db 조회 -> 필터링 

    // CONNECT => ssl connect => GET or POST 요청 recv
    task->remote_fd = connect_remote_http(task->req->host, task->req->port);
    // remote ssl 연결
    task->remote_ssl = connect_remote_https(task->remote_fd, task->remote_ctx);
    if(task->remote_ssl==NULL)
    {
        // TO-DO 메모리 해제
        pthread_mutex_lock(&mutex_lock); 
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
        pthread_mutex_unlock(&mutex_lock); 
        return STAT_FAIL;
    }
    task->client_side_https = true;
    task->remote_side_https = true;

    LOG(DEBUG,"Host: %s\n", task->req->host); // 호스트 이름 출력
    LOG(DEBUG,"Port: %d\n", task->req->port); // 포트 출력
    LOG(DEBUG,"CONNECT request for %s:%d\n", task->req->host, task->req->port);
#if 0 /*TO-DO 인증 방식 추가*/
    // client HTTP/1.1 RFC 7235 (Authentication) 
    const char *response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"My Proxy Server\"\r\nContent-Length: 0\r\n\r\n";
    SSL_write(task->client_ssl, response, strlen(response));
    char tmp[1000]={0,};
    recv(task->client_ssl, tmp, strlen(tmp), 0);
    LOG(INFO,"recv data: %s", tmp);
#endif
    // client ssl 연결
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    SSL_write(task->before_client_ssl, response, strlen(response));
    if(setup_ssl_cert(task->req->host, ca_key, ca_cert, &task->client_ctx, &task->client_ssl)){
        exit(1);
    }
    task->sbio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(task->sbio, task->before_client_ssl, BIO_NOCLOSE);
    SSL_set_bio(task->client_ssl, task->sbio, task->sbio);
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
    ev->events = EPOLLIN|EPOLLRDHUP | EPOLLOUT;
    ev->data.ptr = task;
    // set_blocking(task->client_fd);
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
    pthread_mutex_unlock(&mutex_lock); 
    return STAT_OK;
}


int client_read(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    int ret;

    if(task->client_side_https)
    {
        client_read_with_https(task, epoll_fd,ev);
    }
    else
    {
        client_read_with_http(task, epoll_fd,ev);
    }
    return STAT_OK;
}

int client_write(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    if(task->client_side_https == true) 
    {
        client_write_with_https(task, epoll_fd, ev);
    } 
    else 
    {
        client_write_with_http(task, epoll_fd, ev);
    }
    pthread_mutex_lock(&mutex_lock); 
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
    pthread_mutex_unlock(&mutex_lock); 
    return STAT_OK;
}

int remote_read(task_t* task, int epoll_fd, struct epoll_event *ev)
{



    if(task->remote_side_https)
    {
        remote_read_with_https(task, epoll_fd, ev);
    }
    else
    {
        remote_read_with_http(task, epoll_fd, ev);
    }
    return STAT_OK;
}

void* remote_read_process(void *arg)
{
    LOG(DEBUG, "sgseo");
    task_arg_t* taskArg = (task_arg_t*)arg;
    task_t *task = taskArg->task;
    struct epoll_event *ev = taskArg->ev;
    int epoll_fd = taskArg->epoll_fd;
    LOG(DEBUG, "sgseo");
    if(task->remote_side_https)
    {
        LOG(DEBUG, "sgseo");
        remote_read_with_https(task, epoll_fd, ev);
    }
    else
    {
        LOG(DEBUG, "sgseo");
        remote_read_with_http(task, epoll_fd, ev);
    }
    return STAT_OK;
}



int remote_write(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    if(task->remote_side_https)
    {
        remote_write_with_https(task, epoll_fd, ev);
    }
    else
    {
        remote_write_with_http(task, epoll_fd, ev);
    }
    return STAT_OK;
}

void *thread_func(void *data)
{
    int th_idx = *((int*)data);
    // 쓰레드 동기화용 조건변수
    pthread_mutex_lock(&async_mutex);
    pthread_cond_signal(&async_cond);
    pthread_mutex_unlock(&async_mutex);
    LOG(DEBUG, "Thread[%d] create ", th_idx);
    while(1)
    {
        pthread_mutex_lock(&cond_lock);
        pthread_cond_wait(thread_cond[th_idx].cond, &cond_lock);
        LOG(DEBUG, "Thread[%d] work ", th_idx);
        task_arg[th_idx].func(&(task_arg[th_idx]));
        thread_cond[th_idx].busy = 0;
        LOG(DEBUG, "Thread[%d] Done ", th_idx);
        pthread_mutex_unlock(&cond_lock);
    }
}