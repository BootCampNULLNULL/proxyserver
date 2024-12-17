#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <queue>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define SERVERPORT 5051
#define MAX_EVENTS 1000
#define THREAD_POOL_SIZE 8

typedef struct {
        int client_fd;
        char data[1024];
} task_t;

//작업큐
std::queue<task_t*> task_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Non-blocking 설정 함수
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

//실제 대상 서버 통신
static void* connect_remote(void* arg) {
        while(1){
                task_t* task;

                pthread_mutex_lock(&queue_mutex);
                while (task_queue.empty()) {
                        pthread_cond_wait(&queue_cond, &queue_mutex);
                }
                task = task_queue.front();
                task_queue.pop();
                pthread_mutex_unlock(&queue_mutex);

                int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
                set_nonblocking(remote_fd);

                struct sockaddr_in remoteaddr;
                memset(&remoteaddr, 0, sizeof(remoteaddr));
                remoteaddr.sin_family = AF_INET;
                remoteaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                remoteaddr.sin_port = htons(8080);

                connect(remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));

                // 데이터 송신 및 응답 수신
                send(remote_fd, task->data, strlen(task->data), 0); // 송신 길이 수정
                char response[1024];
                memset(&response, 0, sizeof(response));
                int recv_len = recv(remote_fd, response, sizeof(response), 0); // 데이터 수신

                if (recv_len > 0) {
                        printf("%s\n", response);
                        // 클라이언트에 응답 전달
                        send(task->client_fd, response, recv_len, 0);

                } else {
                        perror("recv failed");
                }

                close(remote_fd);
                close(task->client_fd); //응답 전송하고 클라이언트 소켓을 닫음. 세션 유지하는 방식으로 갈지 검토
        }
        return NULL;
}

int main(void) {
        int server_fd, client_fd, bytes;
        socklen_t len;
        struct sockaddr_in seraddr, cliaddr;
        char data[1024];

        //서버 소켓 생성 및 설정정
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        set_nonblocking(server_fd);

        memset(&seraddr, 0, sizeof(seraddr));
        seraddr.sin_family = AF_INET;
        seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        seraddr.sin_port = htons(SERVERPORT);

        if(bind(server_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
                perror("Bind failed");
                close(server_fd);
                exit(EXIT_FAILURE);
        }
        listen(server_fd, 10);
        len = sizeof(cliaddr);

        //epoll 인스턴스스 생성
        int epoll_fd = epoll_create1(0);
        if(epoll_fd == -1) {
                perror("Epoll createion failed");
                close(server_fd);
                exit(EXIT_FAILURE);
        }

        //epoll 이벤트 구조체
        struct epoll_event ev, events[MAX_EVENTS];
        int event_count;
        ev.events = EPOLLIN;
        ev.data.fd = server_fd;

        //epoll 객체에 소켓 등록
        if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
                perror("Epoll control failed");
                close(server_fd);
                close(epoll_fd);
                exit(EXIT_FAILURE);
        }
        
        //스레드 풀 초기화
        pthread_t threads[THREAD_POOL_SIZE];
        for(int i = 0; i < THREAD_POOL_SIZE; i++){
                pthread_create(&threads[i], NULL, connect_remote, NULL);
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
                        if(events[i].data.fd == server_fd) {
                                //새 클라이언트 연결 처리
                                client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                                set_nonblocking(client_fd);
                                ev.events = EPOLLIN;
                                ev.data.fd = client_fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                        } else {
                                //클라이언트 데이터 수신
                                memset(&data, 0, sizeof(data));
                                bytes = recv(client_fd, data, 1024, 0);

                                //0이면 연결 끊김, 0보다 크면 데이터 읽음
                                if(bytes > 0) {
                                        // 작업 큐에 task 추가
                                        task_t* task = (task_t*)malloc(sizeof(task_t));
                                        task->client_fd = events[i].data.fd;
                                        strncpy(task->data, data, bytes);

                                        pthread_mutex_lock(&queue_mutex);
                                        task_queue.push(task);
                                        pthread_cond_signal(&queue_cond);
                                        pthread_mutex_unlock(&queue_mutex);
                                        
                                        // epoll에서 클라이언트 fd 제거
                                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                                } else {
                                        perror("Read failed");
                                        close(events[i].data.fd);
                                }
                        }
                }
                
        }

        close(server_fd);
        close(epoll_fd);
        return 0;
}

//문제점 1. epoll_wait() 함수는 소켓 버퍼에 데이터가 일부라도 도착하면 즉시 이벤트가 발생된걸로 처리하여 반환
//         소켓에 데이터가 온전히 도착하지 않은 상태에서 connect_remote()가 호출되어 문제가 발생할 수 있음 -> http 요청은 \r\n\r\n으로 끝나므로 conncet_remote() 호출 전에 데이터 끝을 확인
//문제점 2. connect_remote()의 로직은 블로킹 IO 방식이므로 실제 대상 서버와의 통신은 비동기 처리가 되지 않음 -> 멀티스레드 구조 적용 필요
//문제점 3. socket을 제대로 닫지 않아, 리소스 누수 발생 -> 소켓 배열 전체를 순회하며 하나씩 close하는 로직 필요