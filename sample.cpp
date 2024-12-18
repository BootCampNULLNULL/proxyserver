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

typedef enum {
        CLIENT_READ,
        CLIENT_WRITE,
        REMOTE_SERVER_READ,
        REMOTE_SERVER_WRITE
} task_state_t;

typedef struct {
        int src_fd;
        int dst_fd;
} task_t;

//작업큐
std::queue<task_t*> task_queue;
pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Non-blocking 설정 함수
static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

//실제 대상 서버 통신
static void* connect_remote(void* arg) {
        while(1){
                task_t* task;

                pthread_mutex_lock(&queue_mutex);       //mutex
                //task queue가 비어있으면, queue_cond가 set되는 것을 기다림 -> 메인에서 작업추가시 queue_cond 세트
                while (task_queue.empty()) {
                        pthread_cond_wait(&queue_cond, &queue_mutex);
                }
                task = task_queue.front();
                task_queue.pop();
                pthread_mutex_unlock(&queue_mutex);

                int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
                //set_nonblocking(remote_fd);

                struct sockaddr_in remoteaddr;
                memset(&remoteaddr, 0, sizeof(remoteaddr));
                remoteaddr.sin_family = AF_INET;
                remoteaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                remoteaddr.sin_port = htons(8080);

                if(connect(remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr)) < 0) {
                        perror("remote server connect failed\n");
                }
                printf("%s\n", task->data);
                // 데이터 송신 및 응답 수신

                send(remote_fd, task->data, 1024, 0); // 송신 길이 수정
                char response[1024];
                memset(&response, 0, 1024);

               //sleep(1000);

                int recv_len = recv(remote_fd, response, 1024, 0); // 데이터 수신

                printf("%s\n", response);

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

//src에서 recv -> dst로 send
static void* thread_worker(void* arg) {
    while (1) {
        task_t* task;

        // 작업 큐에서 작업 가져오기
        pthread_mutex_lock(&queue_mutex);
        while (task_queue.empty()) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        task = task_queue.front();
        task_queue.pop();
        pthread_mutex_unlock(&queue_mutex);

        // 작업 처리 (데이터 중계)
        char buffer[1024];
        int len = recv(task->src_fd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            send(task->dst_fd, buffer, len, 0);
        } else if (len == 0 || (len < 0 && errno != EAGAIN)) {
            // 연결 종료 또는 오류 발생 시 소켓 닫기
            close(task->src_fd);
            close(task->dst_fd);
        }
        free(task);
    }
    return NULL;
}

int main(void) {
        int server_fd, bytes;
        socklen_t len;
        struct sockaddr_in seraddr;
        char data[1024];

        //서버 소켓 생성 및 설정
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

        //epoll 인스턴스 생성
        int epoll_fd = epoll_create1(0);
        if(epoll_fd == -1) {
                perror("Epoll createion failed");
                close(server_fd);
                exit(EXIT_FAILURE);
        }

        //epoll 이벤트 구조체
        struct epoll_event ev, events[MAX_EVENTS];
        ev.events = EPOLLIN;
        ev.data.fd = server_fd;

        //epoll에 서버 소켓 등록
        if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
                perror("Epoll control failed");
                close(server_fd);
                close(epoll_fd);
                exit(EXIT_FAILURE);
        }
        
        //스레드 풀 초기화
        pthread_t threads[THREAD_POOL_SIZE];
        for(int i = 0; i < THREAD_POOL_SIZE; i++){
                pthread_create(&threads[i], NULL, thread_worker, NULL);
        }

        while(1) {
                //이벤트 대기
                int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
                if(event_count == -1) {
                        perror("Epoll wait Failed");
                        break;
                }
                //이벤트에 따른 작업
                for (int i = 0; i < event_count; i++){
                        if(events[i].data.fd == server_fd) {
                                //새 클라이언트 연결 처리
                                struct sockaddr_in cliaddr;
                                socklen_t len = sizeof(cliaddr);
                                int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                                set_nonblocking(client_fd);

                                // epoll에 클라이언트 소켓 등록
                                ev.events = EPOLLIN | EPOLLET;
                                ev.data.fd = client_fd;
                                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                        } else {
                                //클라이언트 데이터 수신
                                memset(&data, 0, sizeof(data));
                                bytes = recv(events[i].data.fd, data, 1024, 0);

                                if(bytes > 0) {
                                        task_t* task = (task_t*)malloc(sizeof(task_t));
                                        task->client_fd = events[i].data.fd;
                                        strncpy(task->data, data, bytes);

                                        pthread_mutex_lock(&queue_mutex);
                                        task_queue.push(task);
                                        pthread_cond_signal(&queue_cond);       //queue_cond 조건 변수를 기다리는 스레드 하나를 깨움
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