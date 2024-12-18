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

#define SERVERPORT 5051
#define MAX_EVENTS 1000

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

// Non-blocking 설정 함수
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
                struct sockaddr_in cliaddr;
                socklen_t len = sizeof(cliaddr);
                int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                if (client_fd < 0) {
                    perror("Accept failed");
                    continue;
                }
                set_nonblocking(client_fd);

                // 클라이언트 소켓을 epoll에 등록
                task_t* task = (task_t*)malloc(sizeof(task_t));
                if (!task) {
                    perror("Task allocation failed");
                    close(client_fd);
                    continue;
                }
                task->client_fd = client_fd;
                task->remote_fd = -1;
                task->buffer_len = 0;
                task->state = STATE_CLIENT_READ;

                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = task;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
                    perror("Epoll add client failed");
                    close(client_fd);
                    free(task);
                    continue;
                }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; // 안전 검사

                if (task->state == STATE_CLIENT_READ) {
                    // 클라이언트 데이터 수신
                    task->buffer_len = recv(task->client_fd, task->buffer, sizeof(task->buffer), 0);
                    if (task->buffer_len > 0) {
                        // 원격 서버 연결 시도
                        task->remote_fd = socket(AF_INET, SOCK_STREAM, 0);
                        if (task->remote_fd < 0) {
                            perror("Remote socket creation failed");
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                            close(task->client_fd);
                            free(task);
                            continue;
                        }
                        set_nonblocking(task->remote_fd);

                        struct sockaddr_in remoteaddr;
                        memset(&remoteaddr, 0, sizeof(remoteaddr));
                        remoteaddr.sin_family = AF_INET;
                        remoteaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                        remoteaddr.sin_port = htons(8080);

                        if (connect(task->remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr)) < 0) {
                            if (errno != EINPROGRESS) {
                                perror("Connect to remote server failed");
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                                close(task->client_fd);
                                close(task->remote_fd);
                                free(task);
                                continue;
                            }
                        }

                        ev.events = EPOLLOUT | EPOLLET;
                        ev.data.ptr = task;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, &ev);

                        task->state = STATE_REMOTE_WRITE;
                    } else if (task->buffer_len == 0 || (task->buffer_len == -1 && errno != EAGAIN)) {
                        // 연결 종료
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                        close(task->client_fd);
                        if (task->remote_fd != -1) close(task->remote_fd);
                        free(task);
                    }
                } else if (task->state == STATE_REMOTE_WRITE) {
                    // 원격 서버로 데이터 송신
                    send(task->remote_fd, task->buffer, task->buffer_len, 0);
                    task->state = STATE_REMOTE_READ;
                    ev.events = EPOLLIN | EPOLLET;
                    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, &ev);
                } else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    task->buffer_len = recv(task->remote_fd, task->buffer, sizeof(task->buffer), 0);
                    if (task->buffer_len > 0) {
                        task->state = STATE_CLIENT_WRITE;
                        ev.events = EPOLLOUT | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                    } else if (task->buffer_len == 0 || (task->buffer_len == -1 && errno != EAGAIN)) {
                        // 원격 서버 연결 종료
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
