#ifndef NET
#define NET
#include "http.h"
#include "ssl_conn.h"
#include "client_side.h"
int is_tls_handshake(const char *data);
int handle_recv_error(int sockfd);
int initial_read(task_t* task);
int recv_data(task_t* task, int epoll_fd);

int connect_remote_http(const char* hostname, int port);
SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx);
void log_exit(const char *fmt, ...);
void* xmalloc(size_t sz);
void set_nonblocking(int fd);
int client_connect_req(task_t* task, int epoll_fd, struct epoll_event *ev);
int client_proxy_ssl_conn(task_t* task, int epoll_fd, struct epoll_event *ev);
int client_connect_req_with_ssl(task_t* task, int epoll_fd, struct epoll_event *ev);

int remote_write(task_t* task, int epoll_fd, struct epoll_event *ev);
int remote_read(task_t* task, int epoll_fd, struct epoll_event *ev);
int client_read(task_t* task, int epoll_fd, struct epoll_event *ev);
int client_write(task_t* task, int epoll_fd, struct epoll_event *ev);

void* remote_read_process(void *arg);
#endif//NET