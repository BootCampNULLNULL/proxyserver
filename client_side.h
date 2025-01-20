#include "http.h"
#include "ssl_conn.h"

#define SERVERPORT 5051
#define MAX_EVENTS 1000
#define DEFUALT_HTTPS_PORT 443
#define DEFUALT_HTTP_PORT 80
#define CERT_FILE "/home/ubuntu/securezone/certificate.pem" // 인증서 파일 경로
#define KEY_FILE  "/home/ubuntu/securezone/private_key.pem"  // 키 파일 경로
#define MAX_BUFFER_SIZE 4096

typedef enum task_state_t {
    STATE_CLIENT_READ,
    STATE_REMOTE_CONNECT,
    STATE_CLIENT_SSL_ACCEPT,
    STATE_CLIENT_SSL_READ,
    STATE_REMOTE_SSL_CONNECT,
    STATE_REMOTE_WRITE,
    STATE_REMOTE_READ,
    STATE_CLIENT_WRITE
} task_state_t;

typedef struct task_t {
    int client_fd;
    bool client_side_https;
    SSL_CTX* client_ctx;
    SSL* client_ssl;
    int remote_fd;
    SSL_CTX* remote_ctx;
    SSL* remote_ssl;
    bool remote_side_https;
    char buffer[MAX_BUFFER_SIZE];
    int buffer_len;
    HTTPRequest* req;
    task_state_t state;
} task_t;

void set_nonblocking(int fd);
void log_exit(const char *fmt, ...);
void* xmalloc(size_t sz);
int get_IP(char* ip_str, const char* hostname, int port);
int connect_remote_http(const char* hostname, int port);
SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx);
