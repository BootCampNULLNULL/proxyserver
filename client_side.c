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
#include "config_parser.h"

EVP_PKEY *ca_key=NULL;
X509 *ca_cert=NULL;

int main(void) {

    initialize_openssl();

    if(load_config()!=STAT_OK)
    {
        LOG(ERROR, "config load error");
    }

    const char *cert_file = get_config_string("CERT_FILE");
    const char *key_file = get_config_string("KEY_FILE");
    int serverport = get_config_int("SERVERPORT");
    ca_key = load_private_key(key_file);
    ca_cert = load_certificate(cert_file);
    if (!ca_key || !ca_cert) {
        fprintf(stderr, "Failed to load CA key or certificate\n");
        exit(EXIT_FAILURE);
    }

    int server_fd;
    struct sockaddr_in seraddr;

    // 서버 소켓 생성 및 설정
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    set_nonblocking(server_fd);

    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    seraddr.sin_port = htons(serverport);

    if (bind(server_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    listen(server_fd, 10);

    // epoll 인스턴스 생성
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("Epoll creation failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 서버 소켓을 epoll에 등록
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("Epoll control failed");
        close(server_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (event_count == -1) {
            if (errno == EINTR) continue; // 신호로 인한 중단은 무시
            perror("Epoll wait failed");
            break;
        }

        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == server_fd) {
                // 새 클라이언트 연결 처리
                while(1) {
                    struct sockaddr_in cliaddr;
                    socklen_t len = sizeof(cliaddr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                    if(client_fd < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK) {
                            // 모든 연결이 처리됨
                            break;
                        } else {
                            perror("Accept failed");
                            break;
                        }
                    }
                    set_nonblocking(client_fd);

                    task_t* task = (task_t*)malloc(sizeof(task_t));
                    
                    task->client_fd = client_fd;
                    task->client_side_https = false;
                    task->client_ssl = NULL;
                    task->client_ctx = NULL;
                    task->remote_fd = -1;
                    task->remote_ctx = NULL;
                    task->remote_ssl = NULL;
                    task->remote_side_https = false;
                    task->buffer_len = 0;
                    task->request_buffer_size = MAX_BUFFER_SIZE;
                    task->request_buffer = (char*)malloc(task->request_buffer_size);
                    task->state = STATE_INITIAL_READ;
                    task->req_method = DEFAULT;

                    ev.events = EPOLLIN;
                    ev.data.ptr = task;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; // 안전 검사
                if(task->state == STATE_INITIAL_READ) {
                    LOG(INFO,  ">> STATE_INITIAL_READ <<");
                    int ret = initial_read(task);
                }
                if (task->state == STATE_CLIENT_READ) {
                    LOG(INFO,  ">> STATE_CLIENT_READ <<");
                    int ret = client_read(task, epoll_fd, &ev);

                    if (ret != STAT_OK) continue;
                }
                else if (task->state == STATE_CLIENT_REQ_PARSE) 
                {
                    LOG(INFO,  ">> STATE_CLIENT_REQ_PARSE <<");
                    int ret = client_req_parse(task, epoll_fd, &ev);
                }
                else if (task->state == STATE_CLIENT_WRITE)
                {
                    LOG(INFO,  ">> STATE_CLIENT_WRITE <<");
                    int ret = client_write(task, epoll_fd, &ev);
                }
                else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    // recv 값 유효성 검사해서 유효하지 못한 응답일 경우 소켓 닫는 로직 필요
                    LOG(INFO,  ">> STATE_REMOTE_READ <<");
                    int ret = remote_read(task, epoll_fd, &ev);
                } 
                else if (task->state == STATE_REMOTE_WRITE) {
                    LOG(INFO,  ">> STATE_REMOTE_WRITE <<");
                    int ret = remote_write(task, epoll_fd, &ev);  
                } 
                else if (task->state == STATE_CLIENT_PROXY_SSL_CONN)
                {
                    LOG(INFO,  ">> STATE_CLIENT_PROXY_SSL_CONN <<");
                    int ret = client_proxy_ssl_conn(task, epoll_fd, &ev);
                }
            }
        }
    }
    close(server_fd);
    close(epoll_fd);
    
    return 0;
}

// 문제점 1. STATE_CLIENT_WRITE 상태에서 클라이언트로 최종 수신 종료 이후 세션 유지 or 종료
// 문제점 2. 응답 버퍼 크기 초과 데이터 고려 필요요