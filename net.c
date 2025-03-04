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
#include "sc_mem_pool.h"
extern EVP_PKEY *ca_key;
extern X509 *ca_cert;

int check_valid_http_request(task_t* task) 
{
    if(task->req_method == STATE_GET || task->req_method == STATE_HEAD || task->req_method == STATE_CONNECT) {
        char CRLF[4] = {0x0D, 0x0A, 0x0D, 0x0A};
        char valid_check[4];

        memcpy(valid_check, task->buffer + task->buffer_len - 4, 4);

        if (CRLF[0] == valid_check[0] && CRLF[1] == valid_check[1] && CRLF[2] == valid_check[2] && CRLF[3] == valid_check[3]) {
            return STAT_OK;
        } else {
            return -1;
        }
    } else if(task->req_method == STATE_POST) {

    }
    

}

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

task_t* create_task(void) {
    
    task_t* task = (task_t*)malloc(sizeof(task_t));
                    
    task->client_fd = -1;
    task->client_side_https = false;
    task->remote_side_https = false;
    task->client_ssl = NULL;
    task->client_ctx = NULL;
    task->before_client_ctx = NULL;
    task->before_client_ssl = NULL;
    task->remote_fd = -2;
    task->remote_ctx = NULL;
    task->remote_ssl = NULL;
    task->sbio = NULL;
    
    task->pool = sc_create_pool(MAX_BUFFER_SIZE);
    task->buffer = NULL;
    // if (task->buffer == NULL) {
    //     task->buffer = sc_palloc(task->pool, MAX_BUFFER_SIZE);
    //     if (!task->buffer) {
    //         perror("메모리 풀에서 버퍼 할당 실패");
    //         return -1;
    //     }
    // }

    
    task->buffer_len = 0;
    task->request_buffer_size = MAX_BUFFER_SIZE;

    // task->request_buffer = (char*)malloc(task->request_buffer_size);
    task->state = STATE_INITIAL_READ;
    task->req = NULL;
    task->req_method = DEFAULT;
    task->sent_bytes = 0;
    task->auth = false;

    return task;
}

void free_task(task_t* task, const int p_epoll_fd) {
    if(task->req != NULL) {
        free_request(task->req);
    }

    // if(task->request_buffer != NULL) {
    //     free(task->request_buffer);
    // }
    
    // if(task->response_buffer != NULL) {
    //     free(task->response_buffer);
    // }

    if(task->before_client_ssl != NULL) {
        BIO_free(task->sbio);
        SSL_free(task->before_client_ssl);
        SSL_CTX_free(task->before_client_ctx);
    }

    if(task->client_ssl != NULL) {
        SSL_free(task->client_ssl);
        SSL_CTX_free(task->client_ctx);
    }

    if(task->remote_ssl != NULL) {
        SSL_free(task->remote_ssl);
        SSL_CTX_free(task->remote_ctx);
    }
    if(task->remote_fd) {
        epoll_ctl(p_epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
        close(task->remote_fd);
    }
    
    if(task->client_fd) {
        epoll_ctl(p_epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
        close(task->client_fd);
    }

    free(task);
}

/**
 * @brief 도메인명에서 호스트명 획득하여 remote 서버와 통신을 위한 fd 생성
 * 
 * @param hostname 
 * @param port 
 * @return int file descriptor
 */
int connect_remote_http(HTTPString hostname, int port)
{
    char* r_hostname = HTTPString_to_value(hostname);
    struct hostent *host;
    if((host = gethostbyname(r_hostname)) == NULL) {
        perror(r_hostname);
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
            printf("Remote SSL Handshake Success\n");
            return remote_ssl;
        } else {
            int err = SSL_get_error(remote_ssl, ret);
            switch(err) {
                case SSL_ERROR_WANT_READ:
                    continue;
                case SSL_ERROR_WANT_WRITE:
                    continue;
                default:
                    printf("Client SSL Handshake error - %d\n", err);
                    exit(1);
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
        printf("recv() - No data available, try again later\n");
    } else if (errno == ECONNRESET) {
        // 상대방이 연결을 강제 종료한 경우
        printf("recv() - Connection reset by peer\n");
        close(sockfd);
    } else if (errno == EINTR) {
        // 인터럽트로 인해 recv()가 중단된 경우, 다시 시도 가능
        printf("recv() - Interrupted by signal, retrying...\n");
    } else {
        // 기타 오류
        printf("recv() - Error: %s\n", strerror(errno));
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

int check_req_method(task_t* task) {
    if(str3_cmp(task->buffer, 'G', 'E', 'T')) {
        task->req_method = STATE_GET;
        return STAT_OK;
    } else if(str4_cmp(task->buffer, 'P', 'O', 'S', 'T')) {
        task->req_method = STATE_POST;
        return STAT_OK;
    } else if(str3_cmp(task->buffer, 'P', 'U', 'T')) {
        task->req_method = STATE_PUT;
        return STAT_OK;
    } else if(str4_cmp(task->buffer, 'H', 'E', 'A', 'D')) {
        task->req_method = STATE_HEAD;
        return STAT_OK;
    } else if(str7_cmp(task->buffer, 'C', 'O', 'N', 'N', 'E', 'C', 'T')) {
        task->req_method = STATE_CONNECT;
        return STAT_OK;
    } else if(str7_cmp(task->buffer, 'O', 'P', 'T', 'I', 'O', 'N', 'S')) {
        task->req_method = STATE_OPTIONS;
        return STAT_OK;
    } else if(str6_cmp(task->buffer, 'D', 'E', 'L', 'E', 'T', 'E')) {
        task->req_method = STATE_DELETE;
        return STAT_OK;
    } else if(str5_cmp(task->buffer, 'T', 'R', 'A', 'C', 'E')) {
        task->req_method = STATE_TRACE;
        return STAT_OK;
    } else {
        printf("Invalid Request Method\n");
        return -1;
    }
}

int initial_read(task_t* task)
{
    task->buffer = sc_palloc(task->pool, MAX_BUFFER_SIZE);
    ssize_t buf_size = recv(task->client_fd, task->buffer, MAX_BUFFER_SIZE, MSG_PEEK);

    if(handle_recv_error(task->client_fd)!=STAT_OK)
    {
        return -1;
    }


    // https to https
    if(is_tls_handshake(task->buffer))
    {
        //tls_handshake에 이용할 SSL 객체 셋팅
        //TO-DO proxy server ip에 맞게 인증서 생성하는 로직 필요
        task->client_ctx = SSL_CTX_new(TLS_server_method());
        if (!SSL_CTX_use_certificate_file(task->client_ctx, "/home/ubuntu/securezone/proxy.pem", SSL_FILETYPE_PEM)) {
            perror("Failed to load certificate from file");
            SSL_CTX_free(task->client_ctx);
            // EVP_PKEY_free(key); //sgseo free TO-DO
            // X509_free(dynamic_cert);
            // close(client_sock);
            // free_task(task);
            return NULL;
        }

        if (!SSL_CTX_use_PrivateKey_file(task->client_ctx, "/home/ubuntu/securezone/proxy_key.pem", SSL_FILETYPE_PEM)) {
            perror("Failed to load private key from file");
            SSL_CTX_free(task->client_ctx);
            // EVP_PKEY_free(key);
            // X509_free(dynamic_cert);
            // close(client_sock);
            return NULL;
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


int recv_data(task_t* task, int epoll_fd, struct epoll_event* ev)
{
// 클라이언트 데이터 수신
    if (task->buffer == NULL) {
        task->buffer = sc_palloc(task->pool, MAX_BUFFER_SIZE);
        if (!task->buffer) {
            perror("메모리 풀에서 버퍼 할당 실패");
            return -1;
        }
    }
    
    // client 요청 recv
    int ret = recv(task->client_fd, task->buffer + task->buffer_len, MAX_BUFFER_SIZE, 0);

    if (ret > 0) {
        task->buffer_len += ret;

        // 버퍼가 가득 찼을 때, 추가 메모리 할당
        if (task->buffer_len >= task->pool->pool_size) {
            sc_palloc(task->pool, MAX_BUFFER_SIZE);  // 새 풀 할당
            printf("추가 메모리 할당 (버퍼 크기 증가)\n");
        }

        // 요청 처리 준비 완료
        if (ret < MAX_BUFFER_SIZE) {
            task->state = STATE_CLIENT_REQ_PARSE;
            ev->events = EPOLLOUT;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
        }

        return STAT_OK;
    } else if (ret == 0) {
        // 클라이언트 연결 종료
        printf("Client disconnected\n");
        free_task(task, epoll_fd);
        return -2;
    } else {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // 더 이상 읽을 데이터가 없음
            if (task->buffer_len > 0) {
                task->state = STATE_CLIENT_REQ_PARSE;
                ev->events = EPOLLOUT;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
                return STAT_OK;
            }
            return STAT_EAGAIN;
        } else {
            // 수신 실패
            perror("recv failed");
            free_task(task, epoll_fd);
            return -3;
        }
    }

    return STAT_OK;
}



// int recv_data(task_t* task, int epoll_fd, struct epoll_event* ev)
// {
// // 클라이언트 데이터 수신
//     memset(task->buffer, 0, MAX_BUFFER_SIZE);
    
//     // client 요청 recv
//     int ret = recv(task->client_fd, task->buffer, MAX_BUFFER_SIZE, 0);

//     if (ret > 0) {
//         // MAX_BUFFER_SIZE 
//         if (ret < MAX_BUFFER_SIZE) {
//             task->buffer_len = task->buffer_len + ret;
//             // task->state = STATE_CLIENT_REQ_PARSE;

//             // ev->events = EPOLLOUT;
//             // epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
//             return STAT_OK;
//         } else if (ret == MAX_BUFFER_SIZE) {
//             // 버퍼 늘림
//             return STAT_OK;
//         }
        
//     } else if (ret == 0) {
//         // 클라이언트 연결 종료
//         printf("Client disconnected\n");
//         free_task(task, epoll_fd);
//         return -2;
//     } else {
//         if (errno == EAGAIN || errno == EWOULDBLOCK) {
//             // 읽을 데이터가 더 이상 없음
//             if(task->buffer_len > 0) {  // 데이터를 읽고 더이상 읽을게 없는 경우
//                 task->state = STATE_CLIENT_REQ_PARSE;
//                 ev->events = EPOLLOUT;
//                 epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
//                 return STAT_OK;
//             }
//             return STAT_EAGAIN;         // 소켓에 데이터가 아직 안 온 경우
//         } else {
//             // recv 실패
//             perror("recv failed");
//             free_task(task, epoll_fd);
//             return -3;
//         }
//     }
//     return STAT_OK;

// }

/**
 * @brief http 프로토콜로 client data read
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */

int client_req_parse(task_t* task, int epoll_fd, struct epoll_event *ev) 
{
    task->req = read_request(task->buffer);

    //method CONNECT 일때
    if(!strncmp(task->req->method.start,"CONNECT", 7)){
        return client_connect_req(task, epoll_fd, ev);
    }

    // url db 조회 -> 필터링 
    if(task->req->port == -1) {
        task->req->port = DEFUALT_HTTP_PORT;
    }

    // remote 연결
    task->remote_fd = connect_remote_http(task->req->host, task->req->port);
    printf("remote connection success\n");

    ev->events = EPOLLOUT;
    ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);

    task->state = STATE_REMOTE_WRITE;
    // free(req);  
    return STAT_OK;
}

int client_read_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    // 클라이언트 데이터 수신
    // memset(task->buffer, 0, MAX_BUFFER_SIZE);

    // client 요청 recv
    int ret = recv_data(task, epoll_fd, ev);

    if(ret != STAT_OK) return -1;

    if(check_req_method(task) != STAT_OK) return -1;

    if(check_valid_http_request(task) == STAT_OK) {
        printf("Data received from client: %d bytes\n", task->buffer_len);
        printf("%.*s\n", task->buffer_len, task->buffer);

        task->state = STATE_CLIENT_REQ_PARSE;

        
        ev->events = EPOLLOUT;
        
        //
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
        //
        
        return STAT_OK;
    }
    
    printf("Data received from client: %d bytes\n", task->buffer_len);
    printf("%.*s\n", task->buffer_len, task->buffer); // 안전하게 출력
    
    return STAT_OK;

    // http 요청 로깅

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
            continue;
        } else if (ret == 0) {
            printf("Client disconnected\n");
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
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
                printf("Client SSL Read error - %d\n", err);
                exit(1);
            }
        }
    }

    printf("Data received from client: %d bytes\n", task->buffer_len);
    printf("%s\n", task->buffer);

    free_request(task->req);
    task->req = read_request(task->buffer);

    if(!strncmp(task->req->method.start,"CONNECT",7))
    {
        //client <-https-> proxy <-https-> remote인 경우
        //SSL 암호화 연결 상태에서 CONNECT method 처리
        return client_connect_req_with_ssl(task, epoll_fd, ev);
    }

    if(task->req->port == -1) {
        task->req->port = DEFUALT_HTTPS_PORT;
    }
    task->state = STATE_REMOTE_WRITE;
    ev->events = EPOLLOUT;
    ev->data.ptr = task;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, ev);

    
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
    free_task(task, epoll_fd);
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
    free_task(task, epoll_fd);
    // 세션 유지시
    // task->state = STATE_CLIENT_READ;
    // ev->events = EPOLLIN | EPOLLET;
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
    // int ret = recv(task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
    // LOG(INFO,"remote read result: %d", ret);
    // if (ret > 0) {
    //     //TO-DO 호출 함수 수정 필요

    //     int ret2;
    //     if(task->client_side_https) ret2 = SSL_write(task->client_ssl, task->buffer,ret);
    //     else ret2 = send(task->client_fd, task->buffer,ret,0);
    //     task->buffer_len = task->buffer_len + ret;

    // } else if (ret == 0) {
    //     // remote 연결 종료
    //     printf("remote disconnected\n");
    //     if (task->buffer_len == 0) {    // 클라이언트에 응답 전송 전에 remote 연결이 끊겼을때
    //         free_task(task, epoll_fd);
    //         return -1;
    //     } else {
    //         free_task(task, epoll_fd);
    //         return -1;
    //     }
    // } else {
    //     if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //         // 읽을 데이터가 더 이상 없음
    //         // sgseo TO-DO 데이터를 다 읽어서 읽을 데이터가 없는 상황일 수 있는데,, 그럴때는 어떻게 해야되는지 처리 필요
    //         if (task->buffer_len > 0) {
    //             printf("Remote to Client Send Success\n");
    //             free_task(task, epoll_fd);
    //         }
    //         printf("No data to read on remote read with http\n");
    //         ev->events = EPOLLIN;
    //         ev->data.ptr = task;
    //         epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
    //     } else {
    //         // recv 실패
    //         perror("recv failed");
    //         epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
    //         epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
    //         close(task->client_fd);
    //         close(task->remote_fd);
    //         free(task);
    //         exit(1);
    //     }
    // }
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
            printf("remote disconnected\n");
            if (task->buffer_len == 0) {    // 클라이언트에 응답 전송 전에 remote 연결이 끊겼을때
                free_task(task, epoll_fd);
                break;
            } else {
                free_task(task, epoll_fd);
                break;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 읽을 데이터가 더 이상 없음 
                // sgseo TO-DO 데이터를 다 읽어서 읽을 데이터가 없는 상황일 수 있는데,, 그럴때는 어떻게 해야되는지 처리 필요
                if (task->buffer_len > 0) {
                    printf("Remote to Client Send Success\n");
                    free_task(task, epoll_fd);
                    break;
                }
                printf("No data to read on remote read with http\n");
                ev->events = EPOLLIN;
                ev->data.ptr = task;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                break;
            } else {
                // recv 실패
                perror("recv failed");
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
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
        ev->events = EPOLLOUT | EPOLLET;
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
            printf("remote disconnected\n");
            if (task->buffer_len == 0) {
                free_task(task, epoll_fd);
                break;
            } else {
                free_task(task, epoll_fd);
                break;
            }
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if(err == SSL_ERROR_WANT_READ) LOG(DEBUG, "SSL_read result: SSL_ERROR_WANT_READ");
            else if(err == SSL_ERROR_WANT_WRITE) LOG(DEBUG, "SSL_read result: SSL_ERROR_WANT_WRITE");
            else LOG(ERROR, "SSL_read error %d",err);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                if(task->buffer_len > 0) {
                    printf("Remote to Client SSL_Write Success\n");
                    free_task(task, epoll_fd);
                    break;
                }
                printf("No data to read remote read with https\n");
                ev->events = EPOLLIN;
                ev->data.ptr = task;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                // SSL_read finished
        
                break;
            } else {
                printf("Remote SSL Read error - %d\n", err);
                exit(1);
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
        ev->events = EPOLLOUT | EPOLLET;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
    }
#endif
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
    // ssize_t ret = send(task->remote_fd, task->buffer + task->sent_bytes, task->buffer_len, 0);
    // if (ret > 0) {
    //     if(ret == task->buffer_len) {   // send 완료
    //         task->sent_bytes = 0;
    //         task->state = STATE_REMOTE_READ;
    //         ev->events = EPOLLIN;
    //         epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
    //         return STAT_OK;
    //     } else {    // send 미완료
    //         task->buffer_len = task->buffer_len - ret;   // 전송한 만큼 차감
    //         task->sent_bytes = task->sent_bytes + ret;   // 전송한 만큼 버퍼 이동 후 send
    //         return -1;
    //     }
    // } else if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) { // 소켓에 버퍼 준비 안됨
    //     if (errno == EAGAIN || EWOULDBLOCK ) {
    //         printf("Send buffer full, waiting for EPOLLOUT event...\n");
    //         ev->events = EPOLLOUT;
    //         epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
    //         return -1;
    //     } else if (errno == EPIPE) {
    //         printf("Broken pipe: Connection closed by peer.\n");
    //         exit(1);
    //     } else {
    //         perror("send failed");
    //         exit(1);
    //     }
    // } else {
    //     // send 실패 처리
    //     perror("send failed");
    //     exit(1);
    // }

    ssize_t sent_bytes = 0;
    while (task->buffer_len > 0) {
        ssize_t ret = send(task->remote_fd, task->buffer + sent_bytes, task->buffer_len, 0);
        if (ret > 0) {
            sent_bytes += ret;
            task->buffer_len -= ret;

            // 모든 데이터를 전송 완료한 경우
            if (task->buffer_len == 0) {
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                break;
            }
        } else if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (errno == EAGAIN || EWOULDBLOCK ) {
                printf("Send buffer full, waiting for EPOLLOUT event...\n");
                ev->events = EPOLLOUT;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                break;
            } else if (errno == EPIPE) {
                printf("Broken pipe: Connection closed by peer.\n");
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
        if (ret > 0) {
            sent_bytes += ret;
            task->buffer_len -= ret;

            // 모든 데이터를 전송 완료한 경우
            if (task->buffer_len == 0) {
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                break;
            }
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                printf("Send buffer full, waiting for EPOLLOUT event...\n");
                ev->events = EPOLLOUT;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, ev);
                break; 
            } else {
                // SSL_write 실패 처리
                printf("Remote SSL Write error: %d\n", err);
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
    while(1)
    {
        int ret = SSL_accept(task->client_ssl);
        if (ret == 1) {
            printf("Client SSL Handshake Success\n");
            task->state = STATE_CLIENT_READ;
            task->client_side_https = true;
            ev->events = EPOLLIN;
            ev->data.ptr = task;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
            return STAT_OK;
        }
        // SSL_accept가 완료되지 않은 경우
        int err = SSL_get_error(task->client_ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
                continue;
            case SSL_ERROR_WANT_WRITE:
                continue;
            default:
                printf("Client SSL Handshake error - %d\n", err);
                exit(1);
        }
    }
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
    task->remote_fd = connect_remote_http(task->req->host, task->req->port);    // 소켓 connect만
    // remote ssl 연결
    task->remote_ssl = connect_remote_https(task->remote_fd, task->remote_ctx); // 
    task->client_side_https = true;
    task->remote_side_https = true;
    // if(task->req->port == -1) {
    //     task->req->port = DEFUALT_HTTPS_PORT;
    // }
    printf("Host: %s\n", task->req->host); // 호스트 이름 출력
    printf("Port: %d\n", task->req->port); // 포트 출력
    printf("CONNECT request for %s:%d\n", task->req->host, task->req->port);
#if 0 /*TO-DO 인증 방식 추가*/
    // client HTTP/1.1 RFC 7235 (Authentication) 
    const char *response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"My Proxy Server\"\r\nContent-Length: 0\r\n\r\n";
    send(task->client_fd, response, strlen(response), 0);
    char tmp[1000]={0,};
    recv(task->client_fd, tmp, strlen(tmp), 0);
    LOG(INFO,"recv data: %s", tmp);
#endif
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(task->client_fd, response, strlen(response), 0);
    if(setup_ssl_cert(task->req->host.start, ca_key, ca_cert, &task->client_ctx, &task->client_ssl)){
        exit(1);
    }
    SSL_set_fd(task->client_ssl, task->client_fd);
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
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
    task->client_side_https = true;
    task->remote_side_https = true;

    // printf("Host: %s\n", task->req->host); // 호스트 이름 출력
    // printf("Port: %d\n", task->req->port); // 포트 출력
    // printf("CONNECT request for %s:%d\n", task->req->host, task->req->port);
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
    if(setup_ssl_cert(task->req->host.start, ca_key, ca_cert, &task->client_ctx, &task->client_ssl)){
        exit(1);
    }
    task->sbio = BIO_new(BIO_f_ssl());  // SSL BIO 객체 생성
    BIO_set_ssl(task->sbio, task->before_client_ssl, BIO_NOCLOSE);  // 기존 TLS세션을 BIO 객체와 연결 
    SSL_set_bio(task->client_ssl, task->sbio, task->sbio);  // 새 TLS 세션(client_ssl)을 기존 TLS 세션과 연결
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
    ev->events = EPOLLIN;
    ev->data.ptr = task;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, ev);
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
        ret = client_read_with_http(task, epoll_fd,ev);
        if(ret != STAT_OK) return -1;
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

