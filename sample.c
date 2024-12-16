#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define SERVERPORT 5051
#define MAX_EVENTS 10

static void connect_remote(const int fd, const char* data) {
        //대상 서버와 연결
        int sock_remote_fd;
        char response[1024];
        struct sockaddr_in remoteaddr;
        sock_remote_fd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&remoteaddr, 0, sizeof(remoteaddr));
        remoteaddr.sin_family = AF_INET;
        remoteaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        remoteaddr.sin_port = htons(8080);

        //remote server connect
        connect(sock_remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));
        send(sock_remote_fd, data, strlen(data), 0);    //send data -> http reqeust
        printf("send complete\n");
        recv(sock_remote_fd, response, 1024, 0);        //recv http response -> response buffer
        printf("%s\n", response);
        //printf("%s\n", response);

        send(fd, response, 1024, 0);
        close(sock_remote_fd);
        return;
}

int main(void) {
        int sock_fd, new_fd, bytes, len;
        struct sockaddr_in seraddr, cliaddr;
        char data[1024];
        printf("dd\n");
        //listen socket open
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&seraddr, 0, sizeof(seraddr));
        seraddr.sin_family = AF_INET;
        seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        seraddr.sin_port = htons(SERVERPORT);
        if(bind(sock_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
                perror("Bind failed");
                close(sock_fd);
                exit(EXIT_FAILURE);
        }

        listen(sock_fd, 10);
        len = sizeof(cliaddr);

        //epoll 객체 생성
        int epoll_fd = epoll_create1(0);
        if(epoll_fd == -1) {
                perror("Epoll createion failed");
                close(sock_fd);
                exit(EXIT_FAILURE);
        }

        //epoll 이벤트 구조체
        struct epoll_event ev, events[MAX_EVENTS];
        int event_count;
        ev.events = EPOLLIN;
        ev.data.fd = sock_fd;

        //epoll 객체에 소켓 등록록
        if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &ev) == -1) {
                perror("Epoll control failed");
                close(sock_fd);
                close(epoll_fd);
                exit(EXIT_FAILURE);
        }
        
        while(1) {
                //이벤트 대기
                event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
                if(event_count == -1) {
                        perror("Epoll wait Failed");
                        break;
                }

                //이벤트에 따른 작업
                for (int i = 0; i < event_count; i++){
                        if(events[i].data.fd == sock_fd) {
                                new_fd = accept(sock_fd, (struct sockaddr*)&cliaddr, &len);
                                ev.events = EPOLLIN;
                                ev.data.fd = new_fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_fd, &ev);
                        } else {
                                memset(&data, 0, sizeof(data));
                                bytes = recv(new_fd, data, 1024, 0);

                                //0이면 연결 끊김, 0보다 크면 데이터 읽음음
                                if(bytes == 0) {
                                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                                        close(events[i].data.fd);
                                } else if(bytes > 0) {
                                        connect_remote(events[i].data.fd, data);
                                } else {
                                        perror("Read failed");
                                }
                        }
                }
                //close(new_fd);
        }

        close(sock_fd);
        close(epoll_fd);
        return 0;
}
