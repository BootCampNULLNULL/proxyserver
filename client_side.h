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
#include "sc_mem_pool.h"
//#include mem_pool.h

typedef enum task_state_t {
    STATE_INITIAL_READ, //CLIENT<->PROXY 프로토콜 파싱
    STATE_CLIENT_CONNECT_REQ, //CLIENT<-http->PROXY<-https->REMOTE, CONNECT 요청
    STATE_CLIENT_CONNECT_REQ_WITH_SSL, //CLIENT<-https->PROXY<-https->REMOTE, 암호화된 CONNECT 요청
    STATE_CLIENT_READ,
    STATE_CLIENT_REQ_PARSE,
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
    int client_fd;
    bool client_side_https; //client<->proxy https 통신
    bool remote_side_https; //proxy<->remote https 통신
    SSL_CTX* client_ctx;
    SSL* client_ssl;
    SSL_CTX* before_client_ctx;
    SSL* before_client_ssl;
    int remote_fd;
    SSL_CTX* remote_ctx;
    SSL* remote_ssl;
    BIO* sbio;
    
    // char buffer[MAX_BUFFER_SIZE];
    
    sc_pool_t *pool;
    char* buffer;

    int request_buffer_size;
    Req_Method_State req_method;

    int buffer_len;
    int sent_bytes;
    HTTPRequest* req;
    task_state_t state;
    bool auth;
} task_t;

// void set_nonblocking(int fd);
// void log_exit(const char *fmt, ...);
// void* xmalloc(size_t sz);
// int connect_remote_http(const char* hostname, int port);
// SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx);
#endif //CLIENT_SIDE