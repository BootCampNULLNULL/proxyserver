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
#include "auth.h"
#include "worker.h"
#include "select_user.h"
#include "db_conn.h"
extern EVP_PKEY *ca_key;
extern X509 *ca_cert;

extern thread_cond_t *thread_cond;
extern pthread_mutex_t cond_lock;
extern pthread_mutex_t mutex_lock; 
extern pthread_cond_t async_cond;
extern pthread_mutex_t async_mutex;
extern task_arg_t *task_arg;

extern pthread_mutex_t log_lock; 

// extern __thread int thread_local_var;

void log_exit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    
    va_end(ap);
    //exit(1);
}

void* xmalloc(size_t sz)
{
    void *p;

    p = malloc(sz);
    if (!p) log_exit("failed to allocate memory");
    return p;
}

// void task_release(task_t* task)
// {
//     pthread_mutex_lock(&mutex_lock);
//     client_release(task);
//     remote_release(task);
//     if(task)
//         free(task);
//     task = NULL;
//     pthread_mutex_unlock(&mutex_lock);
// }

/**
 * @brief task 구조체를 해제 및 소켓 닫기
 * 
 * @param task 
 */
void client_release(task_t* task)
{
    int error = 0;
    int ret =0;
    socklen_t len = sizeof(error);
    if (task->client_ssl) {
        int ret = SSL_shutdown(task->client_ssl);
        if(ret == 0)
        {
            SSL_shutdown(task->client_ssl); //양방향 종료 안되면 0 return, 한번 더 호출해야함
        }
        SSL_free(task->client_ssl);
        task->client_ssl = NULL;
    }
    //TODO ssl free 전에 ctx free 하도록, ctx에 값 저장 되도록 수정
    if (task->client_ctx) {
        SSL_CTX_free(task->client_ctx);
        task->client_ctx = NULL;
    }
    if (task->req) {
        free_request(task->req);
    }
    ret = getsockopt(*task->client_fd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (!(ret==-1 && errno==EBADF)) {
        //소켓이 이미 닫혀있지 않은 경우
        close(*task->client_fd);
    }
    *task->client_fd = -1;
}

/**
 * @brief remote task 구조체를 해제 및 소켓 닫기
 * 
 * @param task 
 */
void remote_release(task_t* task)
{
    int error = 0;
    int ret =0;
    socklen_t len = sizeof(error);
    if (task->remote_ssl) {
        int ret = SSL_shutdown(task->remote_ssl);
        if(ret == 0)
        {
            SSL_shutdown(task->remote_ssl);
        }
        SSL_free(task->remote_ssl);
        task->remote_ssl = NULL;
    }
    if (task->remote_ctx) {
        SSL_CTX_free(task->remote_ctx);
        task->remote_ctx = NULL;
    }
    ret = getsockopt(*task->remote_fd, SOL_SOCKET, SO_ERROR, &error, &len);
    if (!(ret==-1 && errno==EBADF)) {
        //소켓이 이미 닫혀있지 않은 경우
        close(*task->remote_fd);
    }
    *task->remote_fd = -1;
}

//TODO ssl ctx 메모리 저장 제대로 해서 free 필요,
void release(task_t* task){
    if(*task->client_fd == -1 && *task->remote_fd == -1)
    {
        LOG(INFO, "client_fd[%d] remote_fd[%d] already closed", *task->client_fd, *task->remote_fd);
        free(task->client_fd);
        free(task->remote_fd);
        free(task);
        return;
    }
    //client release
    int error = 0;
    int ret =0;
    socklen_t len = sizeof(error);
    if (task->client_ssl) {
        int ret = SSL_shutdown(task->client_ssl);
        if(ret == 0)
        {
            SSL_shutdown(task->client_ssl); //양방향 종료 안되면 0 return, 한번 더 호출해야함
        }
        if (task->client_ctx) {
            SSL_CTX_free(task->client_ctx);
            task->client_ctx = NULL;
        }
        SSL_free(task->client_ssl);
        task->client_ssl = NULL;
    }
    if (task->req) {
        free_request(task->req);
    }
    if(*task->client_fd != -1)
    {
        ret = getsockopt(*task->client_fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (!(ret==-1 && errno==EBADF)) {
            //소켓이 이미 닫혀있지 않은 경우
            close(*task->client_fd);
        }
    }

    if(task->client_fd){
        *task->client_fd = -1;
    }

    //remote release
    error = 0;
    ret =0;
    len = sizeof(error);
    if (task->remote_ssl) {
        int ret = SSL_shutdown(task->remote_ssl);
        if(ret == 0)
        {
            SSL_shutdown(task->remote_ssl);
        }
        if (task->remote_ctx) {
            SSL_CTX_free(task->remote_ctx);
            task->remote_ctx = NULL;
        }
        SSL_free(task->remote_ssl);
        task->remote_ssl = NULL;
    }
    if(*task->remote_fd != -1)
    {
        ret = getsockopt(*task->remote_fd, SOL_SOCKET, SO_ERROR, &error, &len);
        if (!(ret==-1 && errno==EBADF)) {
            //소켓이 이미 닫혀있지 않은 경우
            close(*task->remote_fd);
        }
    }
    if(task->remote_fd){
        *task->remote_fd = -1;
    }
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
    fcntl(fd, F_SETFL, flags);
}


void print_client_ip(int client_fd, char *ipstr) {
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    if (getpeername(client_fd, (struct sockaddr*)&addr, &len) == -1) {
        perror("getpeername");
        return;
    }

    if (addr.ss_family == AF_INET) {
        // IPv4
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &s->sin_addr, ipstr, INET6_ADDRSTRLEN);
    } else {
        // IPv6
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, INET6_ADDRSTRLEN);
    }

    LOG(DEBUG, "Client IP: %s\n", ipstr);
}

/**
 * @brief thread safe 한 getaddrinfo 함수로 수정
 * 
 * @param hostname 
 * @param port 
 * @return int 
 */
int connect_remote_http(const char *hostname, int port, bool is_https) {
    struct addrinfo hints, *res, *p;
    int sockfd;
    int status;
    const char port_str[6];  // 최대 5자리 숫자 + null
    //https 만 가정
    if(port == -1)
    {
        if(is_https)
            port = DEFUALT_HTTPS_PORT;
        else
            port = DEFUALT_HTTP_PORT;
    }
    snprintf(port_str, sizeof(port_str), "%d", port);

    // hints 설정
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;        // IPv4 (AF_UNSPEC: IPv4 + IPv6)
    hints.ai_socktype = SOCK_STREAM;  // TCP

    
    // getaddrinfo 호출
    if ((status = getaddrinfo(hostname, port_str, &hints, &res)) != 0) {
        LOG(ERROR, "getaddrinfo error: %s hostname[%s], port[%s]", gai_strerror(status), hostname, port_str);
        return STAT_FAIL;
    }

    // 주소 목록 순회하며 connect 시도
    for (p = res; p != NULL; p = p->ai_next) {
        // 소켓 생성
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            LOG(ERROR, "remote socket open error");
            continue;
        }

        // 서버에 연결
        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            LOG(ERROR, "remote socket connect error");
            close(sockfd);
            continue;
        }
        char ip_str[INET_ADDRSTRLEN];  // INET_ADDRSTRLEN = 16
        inet_ntop(AF_INET, p->ai_addr, ip_str, INET_ADDRSTRLEN);
        LOG(DEBUG, "remote ip: %s", ip_str);

        break; // 연결 성공
    }

    freeaddrinfo(res); // 반드시 해제

    if (p == NULL) {
        LOG(ERROR, "Failed to connect to %s:%s\n", hostname, port_str);
        return -1;
    }

    LOG(DEBUG,"Connected to %s:%s (socket %d)\n", hostname, port_str, sockfd);

    set_nonblocking(sockfd);

    return sockfd;
}

/**
 * @brief remote 서버와 ssl 통신을 위해 SSL 객체 생성
 * 
 * @param remote_fd 
 * @param remote_ctx 
 * @return SSL* 
 */
SSL* connect_remote_https(int remote_fd, SSL_CTX** remote_ctx, const char* host)
{
    // SSL 연결
    *remote_ctx = SSL_CTX_new(TLS_client_method());
    // SSL_CTX_set_min_proto_version(remote_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(*remote_ctx, TLS1_3_VERSION);
    if (!(*remote_ctx)) {
        LOG(ERROR,"Failed to create SSL context for remote server");
        close(remote_fd);
        // //exit(1);
        return NULL;
    }
    SSL_CTX_set_keylog_callback(*remote_ctx, keylog_callback);
    SSL *remote_ssl = SSL_new(*remote_ctx);
    SSL_set_tlsext_host_name(remote_ssl,host);
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
                    // //exit(1);
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
    ssize_t buf_size = recv(*task->client_fd, task->buffer, MAX_BUFFER_SIZE, MSG_PEEK);
    if(buf_size <= 0 )
    {
        if(handle_recv_error(*task->client_fd)!=STAT_OK)
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
        SSL_set_fd(task->client_ssl, *task->client_fd);
        task->state = STATE_CLIENT_PROXY_SSL_CONN;
        task->client_side_https = true;
    }
    else
    {
        task->state = STATE_CLIENT_READ;
    }
    return STAT_OK;
}


int recv_data(task_t* task, int epoll_fd)
{
    // client 요청 recv
    while (1) {
        memset(task->buffer, 0, MAX_BUFFER_SIZE);
        int ret = recv(*task->client_fd, task->buffer, MAX_BUFFER_SIZE, 0);
        if (ret > 0) {
            // 예외 처리 필요
            send(*task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
            continue;
        } else if (ret == 0) {
            // 클라이언트 연결 종료
             
            LOG(ERROR,"Client disconnected\n");
             
            
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
            
            release(task);
            return STAT_FAIL;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 읽을 데이터가 더 이상 없음
                break;
            } else {
                // recv 실패
                LOG(ERROR, "recv failed: %s client port[%d]", strerror(errno), task->client_port);
                release(task);
                return STAT_FAIL;
            }
        }
    }
    return STAT_OK;

}


/**
 * @brief http 프로토콜로 client data read
 * @details CONNECT 요청일 경우 mitm 프록시에서 tls handshake 수행하도록 처리
 *          그 외에는 remote read와 동일, 그대로 bypass
 * 
 * @param task 
 * @param epoll_fd 
 * @param ev 
 * @return int 
 * 성공(0), 실패(others)
 */
int client_read_with_http(task_t* task, int epoll_fd, struct epoll_event *ev)
{
    

    if(task->before_state == STATE_INITIAL_READ){
        // 클라이언트 데이터 수신
        memset(task->buffer, 0, MAX_BUFFER_SIZE);
        task->buffer_len = 0;
        // client 요청 recv
        // if(recv_data(task, epoll_fd)==STAT_FAIL)
        // {
        //     return STAT_FAIL;
        // }
        task->buffer_len = recv(*task->client_fd, task->buffer, MAX_BUFFER_SIZE, 0);

        
        LOG(DEBUG,"Data received from client: %d bytes", task->buffer_len);
        // LOG(DEBUG,"%.*s",task->buffer_len, task->buffer); // 안전하게 출력
        
        
        // http 요청 로깅

    
        task->before_state = STATE_CLIENT_READ;
        // http 요청 파싱
        task->req = read_request(task->buffer);
        if(task->req==NULL)
        {
            //error 처리 필요
             
            LOG(ERROR, "https parsing error");
             
            return STAT_OK;
        }
        //method CONNECT 일때만 요청 url 정책 확인한다
        if(!strncmp(task->req->method,"CONNECT", 7)){
             
            LOG(DEBUG, ">> CONNECT IN <<");
#if 1 /*인증 로직 추가*/
        /*
        [ip를 기준으로 클라이언트 연결 유지]
        1. CONNECT 요청에 인증 정보 있는지 확인
        1.1 인증 정보 있으면 id, pw 유효한지 확인
        2. 요청 ip가 hash table에 존재하는지 확인
        2.1 존재하지 않은면 407 Proxy Authentication Required 응답
        3. 사용자 인증정보가 올바르면 url db 정책 확인
        3.1 정책에 접근 권한 없으면 실패 응답
        4. 정책에 접근 권한 있으면 ssl 연결 이후 remote 서버와 통신 중개
        */      
            //1. CONNECT 요청에 인증 정보 있는지 확인
            char auth_base64[200]={0,};
            char auth_str[200]={0,};
            char ip[INET6_ADDRSTRLEN] = {0,};
            print_client_ip(*task->client_fd, ip);
            if(parse_proxy_authorization(task->buffer, auth_base64, sizeof(auth_base64))==STAT_OK)
            {
                if(auth_base64[0] == 0)
                {
                    //인증 정보 없음
                    LOG(DEBUG, "no auth info");
                    return STAT_FAIL;
                }
                base64_decode(auth_base64, auth_str);
                //TODO 1.1 인증 정보 있으면 id, pw 유효한지 확인
                char *userid = strtok(auth_str, ":");
                char *password = strtok(NULL, ":");
                //pw sha1 암호화
                unsigned char hash[SHA_DIGEST_LENGTH];
                char hex_output[SHA_DIGEST_LENGTH * 2 + 1];
                SHA1((const unsigned char*)password, strlen(password), hash);
                for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
                    sprintf(hex_output + (i * 2), "%02x", hash[i]);
                }
                hex_output[40] = '\0';
                SQLHSTMT stmt = get_tls_db_context();
                if (stmt == NULL) {
                    LOG(ERROR, "stmt is NULL");
                    return -1;
                }
                int cnt_result = count_user_by_user_id_user_pw(stmt, userid, hex_output);
                LOG(DEBUG, "cnt_result: %d", cnt_result);
                if(cnt_result != 1)
                {
                    //인증 정보 오류
                    LOG(DEBUG, "no auth info");
                    LOG(DEBUG, "userid: %s, password: %s", userid, hex_output);
                    
                    char *response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                    "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                                    "Connection: close\r\n"
                                    "Content-Length: 0\r\n"
                                    "\r\n";
                    int result = send(*task->client_fd, response, strlen(response), 0);
                    LOG(DEBUG, "407 Proxy Authentication Required send to client[%d]",result);
                    
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                    release(task);
                    
                    free(task->client_fd);
                    free(task->remote_fd);
                    free(task);
                    return STAT_FAIL;
                }
                LOG(DEBUG, "userid: %s, password: %s", userid, hex_output);
                //인증 정보 올바르면 저장
                set_auth(ip, userid);
                LOG(DEBUG, "userid: %s, password: %s", userid, password);
                LOG(DEBUG, "ip: %s", ip);
                LOG(DEBUG, "hash table: %s", get_auth(ip));
            }
            LOG(DEBUG,"auth_base64: %s", auth_base64);
            LOG(DEBUG, "task buffer: %s", task->buffer); 
            LOG(DEBUG, "auth_str: %s", auth_str);

            //2. 요청 ip가 hash table에 존재하는지 확인
            if(get_auth(ip)==NULL)
            {
                //2.1 존재하지 않은면 407 Proxy Authentication Required 응답
                char *response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                                 "Connection: close\r\n"
                                 "Content-Length: 0\r\n"
                                 "\r\n";
                int result = send(*task->client_fd, response, strlen(response), 0);
                LOG(DEBUG, "407 Proxy Authentication Required send to client[%d]",result);
                //debugging 용도
                //client가 새로운 연결로 요청하는지, 기존 연결로 요청하는지 확인
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                release(task);
                
                free(task->client_fd);
                free(task->remote_fd);
                free(task);
                return STAT_FAIL;
            }
            // TODO 3. 사용자 인증정보가 올바르면 url db 정책 확인
            url_policy_list_t *url_policy_list=NULL;
            int ret = select_policy_by_user_id(get_tls_db_context(), get_auth(ip), &url_policy_list);
            //정책 있음
            if(ret>0){
                while(url_policy_list != NULL)
                {
                    if(strcmp(url_policy_list->url, task->req->host) == 0)
                    {
                        //정책에 따라 접근 제한
                        LOG(DEBUG, "url policy access reject");
                        char *response = "HTTP/1.1 403 Forbidden\r\n"
                                        "Connection: close\r\n"
                                        "Content-Length: 0\r\n"
                                        "\r\n";
                        int result = send(*task->client_fd, response, strlen(response), 0);
                        LOG(DEBUG, "403 Forbidden send to client[%d]",result);
                    }
                    
                    url_policy_list_t *temp = url_policy_list;
                    url_policy_list = url_policy_list->next;
                    free(temp);
                }
            }
#endif
            
#ifdef MULTI_THREAD
        task_arg_t *arg = (task_arg_t*)calloc(1,sizeof(task_arg_t));
        arg->task = (task_t*)calloc(1,sizeof(task_t));
        memcpy(arg->task, task, sizeof(task_t));
        arg->epoll_fd = epoll_fd;
        arg->ev = ev;
        pthread_t thread;
        // 
        // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
        // 
        pthread_create(&thread, NULL, client_connect_req_process, arg);
        pthread_detach(thread);
        return STAT_OK;
    
#else
            return client_connect_req(task, epoll_fd, ev);
#endif
        }
        else{
            //TODO host ip 못 얻어온 경우 예외 처리 필요
            if((*task->remote_fd = connect_remote_http(task->req->host, task->req->port, task->client_side_https))==STAT_FAIL){
                close(*task->client_fd);
                *task->client_fd =-1;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd,NULL);
                
                return STAT_FAIL;
            }
            if(task->buffer_len >0){
                //예외 처리 필요
                send(*task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
                
                task->before_state = STATE_CLIENT_READ;
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);

                task_t* task_remote = (task_t*)calloc(1,sizeof(task_t));
                memcpy(task_remote, task, sizeof(task_t));
                task_remote->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task_remote;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task_remote->remote_fd, ev);
                
            }
            else if(task->buffer_len <= 0){
                if(errno != EAGAIN && errno != EWOULDBLOCK){
                    release(task);
                    return STAT_FAIL;
                }
                else{
                    return STAT_OK;
                }
            }
            return STAT_OK;
        }

    }
    
    if(recv_data(task, epoll_fd)==STAT_FAIL)
    {
        return STAT_FAIL;
    }
    
    // task->state = STATE_REMOTE_WRITE;
    // ev->events = EPOLLOUT ;
    // ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
    // 
    // epoll_ctl(epoll_fd, EPOLL_CTL_ADD, *task->remote_fd, ev);
    // 
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
        memset(task->buffer, 0, MAX_BUFFER_SIZE);
        int ret = SSL_read(task->client_ssl, task->buffer, MAX_BUFFER_SIZE); 
        task->buffer_len += ret;
        if (ret > 0) {
            //바로 write
            //TODO error 처리 필요
            // remote_fd가 유효하지 않은 경우 연결 끊음
            #if 0 /*sgseo55*/
            pthread_mutex_lock(&mutex_lock);
            if(*task->remote_fd == -1)
            {
                pthread_mutex_unlock(&mutex_lock); //재귀락 방지
                LOG(ERROR,"remote fd is -1");
                LOG(ERROR,"client fd[%d], client port[%d]", *task->client_fd, task->client_port);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                client_release(task);
                free(task->remote_fd);
                free(task->client_fd);
                return STAT_FAIL;
            }
            #endif
            int write_result = SSL_write(task->remote_ssl, task->buffer, ret);
            #if 0 /*sgseo55*/
            pthread_mutex_unlock(&mutex_lock);
            #endif
            continue;
        } else if (ret == 0) {
            LOG(ERROR,"Client disconnected");
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
            if(*task->remote_fd!=-1){
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
            }
            release(task);
            break;
        } else {
            int err = SSL_get_error(task->client_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                // SSL_read finished
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
                break;
            } else {
                LOG(INFO,"Client SSL Read error - %d cfd[%d], rfd[%d], client port[%d]", err, *task->client_fd, *task->remote_fd, task->client_port);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                if(*task->remote_fd!=-1){
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                }
                release(task);
                return STAT_FAIL;
            }
        }
    }
     

    
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
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
    // close(*task->remote_fd);
    // close(*task->client_fd);
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
    send(*task->client_fd, task->buffer, task->buffer_len, 0);
    // 세션 유지시
    // task->state = STATE_CLIENT_READ;
    // ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
    // epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
    // free(task->req);

    // TO-DO 세션 종료시 free memory
    // TO-DO error 처리
    // free_request(task->req);
    // SSL_free(task->client_ssl);
    // SSL_free(task->remote_ssl);
    // SSL_CTX_free(task->client_ctx);
    // SSL_CTX_free(task->remote_ctx);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
    // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
    // close(*task->remote_fd);
    // close(*task->client_fd);
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
     // TO-DO 정상화 필요
    
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    task->buffer_len = 0;
    while (1) {
        int ret = recv(*task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
         
        LOG(INFO,"remote read result: %d", ret);
         
        if (ret > 0) {
            //TO-DO 호출 함수 수정 필요
            int ret2;
            if(task->client_side_https) ret2 = SSL_write(task->client_ssl, task->buffer,ret);
            else ret2 = send(*task->client_fd, task->buffer,ret,0);
            task->buffer_len = task->buffer_len + ret;
            continue;
        } else if (ret == 0) {
            // remote 연결 종료
             
            LOG(DEBUG,"remote disconnected\n");
             
            if (task->buffer_len == 0) {
                
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                
                // free_request(task->req); !
                // close(*task->client_fd);
                // close(*task->remote_fd);
                break;
            } else {
                break;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // 읽을 데이터가 더 이상 없음 
                // sgseo TO-DO 데이터를 다 읽어서 읽을 데이터가 없는 상황일 수 있는데,, 그럴때는 어떻게 해야되는지 처리 필요
                 
                LOG(DEBUG,"No data to read\n");
                 
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, *task->remote_fd, ev);
                
                break;
            } else {
                // recv 실패
                LOG(ERROR,"recv failed");
                
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                
                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                // close(*task->client_fd);
                // close(*task->remote_fd);
                free(task);
                // //exit(1);
            }
        }
    }
#if 0 /*remote recv()하고 client send() 반복 하도록 수정*/
    if (task->buffer_len > 0) {
        printf("Data received from remote: %d bytes\n", task->buffer_len);
        printf("%s\n", task->buffer);
        task->state = STATE_CLIENT_WRITE;
        ev->events = EPOLLOUT ;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
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
    memset(task->buffer, 0, MAX_BUFFER_SIZE);
    task->buffer_len = 0;
    
    while(1) {
        //에러 처리 필요
        memset(task->buffer, 0, MAX_BUFFER_SIZE);
        int ret = SSL_read(task->remote_ssl, task->buffer, MAX_BUFFER_SIZE);
        // int ret2 = SSL_write(task->client_ssl, task->buffer, ret);
        //printf("asda\n");
        // LOG(DEBUG, "SSL_read result: %d", ret);
        if (ret > 0) {
            //TODO 호출 함수 수정 필요
            // client_fd가 유효하지 않은 경우 연결 끊음
            // remote_fd가 유효하지 않은 경우 연결 끊음
            int fd_stat = 0;
            int error = 0;
            socklen_t len = sizeof(error);
            /*
            epoll_ctl() 자체는 thread-safe하지만,
            epoll_ctl()을 호출하는 스레드가 다른 스레드와 공유하는 데이터에 접근할 때는, 예를 들어 task->client_ssl, *task->client_fd
            mutex를 사용하여 동기화해야 함
            앞에서 clinet fd 유효성 체크 한다고 해도 write() 호출 직전에 free 되면 crash 난다.
            TODO 이전 client fd가 해제되고 다시 재사용 되는 경우 어떻게 확인할 건지 필요
            */  
            pthread_mutex_lock(&mutex_lock);
            if(*task->client_fd == -1)
            {
                pthread_mutex_unlock(&mutex_lock);
                LOG(ERROR,"client fd is -1");
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                if(*task->client_fd!=-1){
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                }
                release(task);
                return STAT_FAIL;
            }
            int ret2;
            if(task->client_side_https) ret2 = SSL_write(task->client_ssl, task->buffer,ret);
            else ret2 = send(*task->client_fd, task->buffer,ret,0);
            pthread_mutex_unlock(&mutex_lock);
            task->buffer_len = task->buffer_len + ret;
#ifdef MULTI_THREAD
            continue;
#else
            continue;
#endif
        } else if (ret == 0) {
            LOG(DEBUG,"remote disconnected");
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
            if(*task->client_fd!=-1){
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
            }
            release(task);
            break;
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if (err == SSL_ERROR_WANT_READ ) {
                LOG(DEBUG,"SSL_ERROR_WANT_READ");
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->remote_fd, ev);
                break;
            } else {
                LOG(ERROR,"Remote SSL Read error - %d rfd[%d]", err, *task->remote_fd);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                if(*task->client_fd!=-1){
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                }
                release(task);
                break;
            }
        }
    } 
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
        ssize_t ret = send(*task->remote_fd, task->buffer + sent_bytes, task->buffer_len, 0);
        if (ret > 0) {
            sent_bytes += ret;
            task->buffer_len -= ret;

            // 모든 데이터를 전송 완료한 경우
            if (task->buffer_len == 0) {
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->remote_fd, ev);
                
                break;
            }
        } else if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (errno == EAGAIN || EWOULDBLOCK ) {
                 
                LOG(DEBUG,"Send buffer full, waiting for EPOLLOUT event...\n");
                 
                ev->events = EPOLLOUT ;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->remote_fd, ev);
                
                break;
            } else if (errno == EPIPE) {
                 
                LOG(ERROR,"Broken pipe: Connection closed by peer.\n");
                 
                //exit(1);
            } else {
                perror("send failed");
                //exit(1);
            }
        } else {
            // send 실패 처리
            perror("send failed");
            //exit(1);
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
                 
                LOG(INFO,"Success STATE_REMOTE_WRITE");
                 
                task->state = STATE_REMOTE_READ;
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->remote_fd, ev);
                
                memset(task->buffer, 0 , MAX_BUFFER_SIZE);
                break;
            }
        } else {
            int err = SSL_get_error(task->remote_ssl, ret);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                 
                LOG(DEBUG,"Send buffer full, waiting for EPOLLOUT event...\n");
                 
                ev->events = EPOLLOUT ;
                
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->remote_fd, ev);
                
                break; 
            } else {
                // SSL_write 실패 처리
                 
                LOG(ERROR,"Remote SSL Write error: %d\n", err);
                 
                //exit(1);
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
             
            LOG(DEBUG,"Client SSL Handshake Success");
             
            task->state = STATE_CLIENT_READ;
            task->client_side_https = true;
            task->before_state = STATE_CLIENT_PROXY_SSL_CONN;
            ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
            ev->data.ptr = task;
            // set_nonblocking(*task->client_fd);
            
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);

            task_t* task_remote = (task_t*)calloc(1,sizeof(task_t));
            memcpy(task_remote, task, sizeof(task_t));
            task_remote->state = STATE_REMOTE_READ;
            ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
            ev->data.ptr = task_remote;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, *task_remote->remote_fd, ev);
        
            return STAT_OK;
        }
        // SSL_accept가 완료되지 않은 경우
        int err = SSL_get_error(task->client_ssl, ret);
        switch(err) {
            case SSL_ERROR_WANT_READ:
                 
                LOG(DEBUG, "SSL_ERROR_WANT_READ");
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
                break;
            case SSL_ERROR_WANT_WRITE:
                 
                LOG(DEBUG, "SSL_ERROR_WANT_WRITE");
                ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                ev->data.ptr = task;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
                break;
            default:
                // TODO SSL_accept 실패 처리 필요
                if(*task->client_fd!=-1){
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                }
                if(*task->remote_fd!=-1){
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                }
                
                release(task);
                LOG(ERROR,"Client SSL Handshake error(%d) - %s\n", err,strerror(err));
                return STAT_FAIL;
                // //exit(1);
        }
    // }
        return STAT_OK;
    }

    int client_auth(task_t* task, int epoll_fd, struct epoll_event *ev){
        //BASE64 디코딩 및 db 정책 조회
        const char* auth = get_config_string("AUTH");
        char tmp[1000]={0,};
        int result = recv(*task->client_fd, tmp, sizeof(tmp), 0);
        if(result <= 0){
            LOG(DEBUG, "result <= 0");
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                ev->data.ptr = task;       
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
                return STAT_OK;
            }
            else{
                LOG(ERROR, "recv failed: %s ", strerror(errno));
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                release(task);
                return STAT_FAIL;
            }
        }
        if(strcmp(auth,"BASE64") == 0){
            LOG(ERROR, "BASE64 AUTH");
            
            LOG(ERROR, "recv result: %s", tmp);
        }

        // 인증 성공시
        ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
        task->state = STATE_CLIENT_PROXY_SSL_CONN;
        ev->data.ptr = task; 
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
        const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
        send(*task->client_fd, response, strlen(response), 0);
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

    task->client_side_https = true;
    task->remote_side_https = true;
    // LOG(DEBUG, "client_connect_req epoll fd: %d", epoll_fd);
    // url db 조회 -> 필터링 

    // CONNECT => ssl connect => GET or POST 요청 recv
    if((*task->remote_fd = connect_remote_http(task->req->host, task->req->port, task->client_side_https))==STAT_FAIL){
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd,NULL);
        release(task);
        return STAT_FAIL;
    }
    // remote ssl 연결
    task->remote_ssl = connect_remote_https(*task->remote_fd, &task->remote_ctx, task->req->host);
    if(task->remote_ssl==NULL)
    {
        LOG(ERROR, "remote ssl fail [%s]",task->req->host);   
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
        release(task);
        return STAT_FAIL;
    }
    
     
    LOG(DEBUG,"Host: %s\n", task->req->host); // 호스트 이름 출력
    LOG(DEBUG,"Port: %d\n", task->req->port); // 포트 출력
    LOG(DEBUG,"CONNECT request for %s:%d\n", task->req->host, task->req->port);
     
    if(setup_ssl_cert(task->req->host, ca_key, ca_cert, &task->client_ctx, &task->client_ssl)){
        LOG(ERROR, "setup_ssl_cert fail");
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
        release(task);
        return STAT_FAIL;
    }
    SSL_set_fd(task->client_ssl, *task->client_fd);
    ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
    
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
    ev->data.ptr = task;
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(*task->client_fd, response, strlen(response), 0);

    // REMOTE_READ가 먼저 감시 되어 순서 꼬이는 경우 있음
    // task_t* task_remote = (task_t*)calloc(1,sizeof(task_t));
    // memcpy(task_remote, task, sizeof(task_t));
    // task_remote->state = STATE_REMOTE_READ;
    // ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
    // ev->data.ptr = task_remote;
    // epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task_remote->remote_fd, ev);
    
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
    if((*task->remote_fd = connect_remote_http(task->req->host, task->req->port, task->client_side_https))==STAT_FAIL){
        close(*task->client_fd);
        *task->client_fd =-1;
        
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd,NULL);
        
        return STAT_FAIL;
    }
    // remote ssl 연결
    task->remote_ssl = connect_remote_https(*task->remote_fd, &task->remote_ctx, task->req->host);
    if(task->remote_ssl==NULL)
    {
        // TO-DO 메모리 해제
        
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
        
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
        LOG(ERROR, "setup_ssl_cert Fail");
        //exit(1);
    }
    task->sbio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(task->sbio, task->before_client_ssl, BIO_NOCLOSE);
    SSL_set_bio(task->client_ssl, task->sbio, task->sbio);
    task->state = STATE_CLIENT_PROXY_SSL_CONN;
    ev->events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
    ev->data.ptr = task;
    // set_blocking(*task->client_fd);
    
    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, *task->client_fd, ev);
    
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
    
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
    
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
    
    task_arg_t* taskArg = (task_arg_t*)arg;
    task_t *task = taskArg->task;
    struct epoll_event *ev = taskArg->ev;
    int epoll_fd = taskArg->epoll_fd;
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


void* client_connect_req_process(void *arg)
{
    task_arg_t* taskArg = (task_arg_t*)arg;
    task_t *task = taskArg->task;
    struct epoll_event *ev = taskArg->ev;
    int epoll_fd = taskArg->epoll_fd;
    // LOG(DEBUG, "client_connect_req_process epoll fd: %d",epoll_fd);
    client_connect_req(task, epoll_fd, ev);   
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
        //spurious wakeups 방지를 위한 검사
        while(!thread_cond[th_idx].ready){
            pthread_cond_wait(thread_cond[th_idx].cond, &cond_lock);
        }
         
        // LOG(DEBUG, "Thread[%d] work cfd[%d] rfd[%d] req->host[%s]  client port[%d]", th_idx, task_arg[th_idx].*task->client_fd,  task_arg[th_idx].*task->remote_fd, task_arg[th_idx].task->req->host, task_arg[th_idx].task->client_port);

        LOG(DEBUG, "Thread[%d] Work", th_idx);
         
        task_arg[th_idx].func(&(task_arg[th_idx]));
         
        LOG(DEBUG, "Thread[%d] Done ",th_idx);
        
        thread_cond[th_idx].ready = 0;
        pthread_mutex_unlock(&cond_lock);
    }
}