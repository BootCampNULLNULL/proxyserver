#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>

#define SERVERPORT 5051
#define MAX_EVENTS 1000

#define str4_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3


typedef enum {
    STATE_CLIENT_READ,
    STATE_REMOTE_CONNECT,
    STATE_REMOTE_WRITE,
    STATE_REMOTE_READ,
    STATE_CLIENT_WRITE
} task_state_t;

typedef struct {
    int client_fd;
    int remote_fd;
    char buffer[1024];
    int buffer_len;
    task_state_t state;
} task_t;

typedef struct {
    char hostname[24];
    char service[12];
} request_line;

// Non-blocking 설정 함수
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int get_IP(char* ip_str, const char* hostname, const char* service) {
    struct addrinfo hints, *res, *p;
    //char ip_str[INET6_ADDRSTRLEN];  // IPv6도 포함한 크기

    // hints 초기화
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;       // IPv4 또는 IPv6 허용
    hints.ai_socktype = SOCK_STREAM;  // TCP 소켓

    // getaddrinfo 호출
    int status = getaddrinfo("localhost", service, &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 1;
    }

    //printf("IP addresses for %s:\n\n", hostname);

    void *addr;
    const char *ipver;

    // 첫 번째 노드 처리
    if (res->ai_family == AF_INET) {  // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else if (res->ai_family == AF_INET6) {  // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    } else {
        fprintf(stderr, "Unknown address family\n");
        freeaddrinfo(res);
        return 1;
    }

    // IP 주소를 문자열로 변환
    inet_ntop(res->ai_family, addr, ip_str, INET_ADDRSTRLEN);
    printf("  %s: %s\n", ipver, ip_str);

    freeaddrinfo(res);  // 메모리 해제
    return 0;
}

static int get_request_line(const char* buf, char* hostname, char* service) {
    strcpy(hostname, "localhost");
    strcpy(service, "http");
    return 0;
}

static int connect_remote(const char* buf) {
    request_line* req = (request_line*)malloc(sizeof(request_line));

    int req_status = get_request_line(buf, req->hostname, req->service);
    char ip_str[INET_ADDRSTRLEN];
    int addr_status = get_IP(ip_str, req->hostname, req->service);

    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(remote_fd < 0) {
        perror("Remote socket creation failed");
    }
    set_nonblocking(remote_fd);

    // http 요청 파싱 -> 원격 서버 접속 정보를 획득하여 소켓 연결 필요
    // 임시로 localhost:8080 하드코딩
    struct sockaddr_in remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.s_addr = inet_addr(ip_str);

    if(str4_cmp(req->service, 'h', 't', 't', 'p')) {
        remoteaddr.sin_port = htons(8080);
    }

    connect(remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));

    free(req);
    return remote_fd;
}


int main(void) {
    int server_fd;
    struct sockaddr_in seraddr;

    // 서버 소켓 생성 및 설정
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    set_nonblocking(server_fd);

    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    seraddr.sin_port = htons(SERVERPORT);

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
                    task->remote_fd = -1;
                    task->buffer_len = 0;
                    task->state = STATE_CLIENT_READ;

                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = task;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; // 안전 검사

                if (task->state == STATE_CLIENT_READ) {
                    // 클라이언트 데이터 수신
                    while((task->buffer_len = recv(task->client_fd, task->buffer, sizeof(task->buffer), 0)) > 0) {
                        // 원격 서버 연결
                        printf("Data received from client: %d bytes\n", task->buffer_len);
                        printf("%s\n", task->buffer);

                        task->remote_fd = connect_remote(task->buffer);

                        ev.events = EPOLLOUT | EPOLLET;
                        ev.data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, &ev);

                        task->state = STATE_REMOTE_WRITE;
                    }

                    if(task->buffer_len == 0 || (task->buffer_len == -1 && errno != EAGAIN)) {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                        close(task->client_fd);
                        if(task->remote_fd != -1) close(task->remote_fd);
                        free(task);
                    }
                } else if (task->state == STATE_REMOTE_WRITE) {
                    // 원격 서버로 데이터 송신
                    send(task->remote_fd, task->buffer, 129, 0);
                    task->state = STATE_REMOTE_READ;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, &ev);
                } else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    // recv 값 유효성 검사해서 유효하지 못한 응답일 경우 소켓 닫는 로직 필요
                    while ((task->buffer_len = recv(task->remote_fd, task->buffer, sizeof(task->buffer), 0)) > 0) {
                        printf("Data received from remote: %d bytes\n", task->buffer_len);
                        printf("%s\n", task->buffer);

                        // 클라이언트로 데이터 전송 상태로 전환
                        task->state = STATE_CLIENT_WRITE;
                        ev.events = EPOLLOUT | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                    }

                    // 연결 종료 처리
                    if (task->buffer_len == 0) {
                        printf("Remote connection closed\n");
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                        close(task->remote_fd);
                        close(task->client_fd);
                        free(task);
                    } else if (task->buffer_len == -1 && errno != EAGAIN) {
                        perror("Error in recv from remote");
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                        close(task->remote_fd);
                        close(task->client_fd);
                        free(task);
                    }
                } else if (task->state == STATE_CLIENT_WRITE) {
                    send(task->client_fd, task->buffer, task->buffer_len, 0);
                    task->state = STATE_CLIENT_READ;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                }
            }
        }
    }

    close(server_fd);
    close(epoll_fd);
    return 0;
}

// 문제점 1. 긴 요청/응답 처리를 위한 버퍼 크기 고려X
// 문제점 2. HTTP 요청/응답 데이터에 대한 유효성 고려X
// 문제점 3. 실제 대상서버로 접속하는 로직 X