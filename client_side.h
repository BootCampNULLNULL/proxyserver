#ifndef CLIENT_SIDE
#define CLIENT_SIDE
#define SERVERPORT 1235
#define MAX_EVENTS 1000
#define DEFUALT_HTTPS_PORT 443
#define DEFUALT_HTTP_PORT 80
#define CERT_FILE "/home/sgseo/proxyserver/certificate.pem" // 인증서 파일 경로
#define KEY_FILE  "/home/sgseo/proxyserver/private_key.pem"  // 키 파일 경로
#define MAX_BUFFER_SIZE 4096
#include "http.h"
#include "util.h"

typedef enum task_state_t {
    STATE_INITIAL_READ, //CLIENT<->PROXY 프로토콜 파싱
    STATE_CLIENT_CONNECT_REQ, //CLIENT<-http->PROXY<-https->REMOTE, CONNECT 요청
    STATE_CLIENT_CONNECT_REQ_WITH_SSL, //CLIENT<-https->PROXY<-https->REMOTE, 암호화된 CONNECT 요청
    STATE_CLIENT_READ,
    STATE_CLIENT_WRITE,
    STATE_REMOTE_READ,
    STATE_REMOTE_WRITE,
    STATE_CLIENT_READ_WITH_SSL,
    STATE_CLIENT_WRITE_WITH_SSL,
    STATE_REMOTE_READ_WITH_SSL,
    STATE_REMOTE_WRITE_WITH_SSL,
    STATE_CLIENT_PROXY_SSL_CONN,
    STATE_CLIENT_PROXY_SSL_CONN_MITM, //CLIENT<-https->PROXY<-https->REMOTE, REMOTE 대신 PROXY가 CLIENT와 SSL 연결
    STATE_CLIENT_PROXY_SSL_CONN_MITM_WITH_SSL, //CLIENT<-https->PROXY<-https->REMOTE, REMOTE 대신 PROXY가 CLIENT와 암호 통신으로 SSL 연결
    STATE_PROXY_REMOTE_SSL_CONN
} task_state_t;

typedef struct task_t {
    int *client_fd;
    bool client_side_https; //client<->proxy https 통신
    bool remote_side_https; //proxy<->remote https 통신
    SSL_CTX* client_ctx;
    SSL* client_ssl;
    SSL_CTX* before_client_ctx;
    SSL* before_client_ssl;
    int *remote_fd;
    SSL_CTX* remote_ctx;
    SSL* remote_ssl;
    BIO* sbio;
    char buffer[MAX_BUFFER_SIZE];
    int buffer_len;
    HTTPRequest* req;
    task_state_t state;
    task_state_t before_state;
    bool auth;
    time_t current_time;
    int client_port;

} task_t;

// void set_nonblocking(int fd);
// void log_exit(const char *fmt, ...);
// void* xmalloc(size_t sz);
// int connect_remote_http(const char* hostname, int port);
// SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx);

typedef struct task_arg_t{
    task_t *task;
    int epoll_fd;
    struct epoll_event *ev;
    void (*func)(void *);
}task_arg_t;

typedef struct thread_cond_t{
    int ready;
    pthread_cond_t *cond;
    pthread_cond_t *thread_cond_lock;
}thread_cond_t;

#endif //CLIENT_SIDE