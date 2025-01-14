#ifndef CLIENT_SIDE_H
#define CLIENT_SIDE_H

#include "http.h"
#include "ssl_conn.h"

#define SERVERPORT 5051
#define MAX_EVENTS 1000
#define DEFUALT_HTTPS_PORT 443
#define DEFUALT_HTTP_PORT 80
#define CERT_FILE "/home/ubuntu/securezone/certificate.pem" // 인증서 파일 경로
#define KEY_FILE  "/home/ubuntu/securezone/private_key.pem"  // 키 파일 경로

typedef enum task_state_t {
    STATE_CLIENT_READ,
    STATE_REMOTE_CONNECT,
    STATE_REMOTE_WRITE,
    STATE_REMOTE_READ,
    STATE_CLIENT_WRITE
} task_state_t;

typedef struct task_t {
    int client_fd;
    bool client_side_https;
    SSL* client_ssl;
    int remote_fd;
    SSL* remote_ssl;
    bool remote_side_https;
    char buffer[1024];
    int buffer_len;
    HTTPRequest* req;
    task_state_t state;
} task_t;


static void set_nonblocking(int fd);
static void log_exit(const char *fmt, ...);
static void* xmalloc(size_t sz);
static int get_IP(char* ip_str, const char* hostname, int port);
static int connect_remote_http(const char* host, int port);
SSL* connect_remote_https(int remote_fd);

#endif