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
#include <pthread.h>
#include "http.h"
#include "ssl_conn.h"
#include "client_side.h"
#include "net.h"
#include "errcode.h"
#include "log.h"
#include "config_parser.h"
#include "util.h"

EVP_PKEY *ca_key=NULL;
X509 *ca_cert=NULL;
int serverport;
int timeout = 0;
EVP_PKEY *ssl_key=NULL;
//thread 수 
#define MAX_THREAD_POOL 10
//각 thread를 위한 동기화 조건 변수
thread_cond_t *thread_cond;
//각 thread critical section 지정
pthread_mutex_t cond_lock= PTHREAD_MUTEX_INITIALIZER; 
//thread 생성 시 동기화 조건 변수
pthread_cond_t async_cond = PTHREAD_COND_INITIALIZER;
//thread 생성 시 동기화용
pthread_mutex_t async_mutex = PTHREAD_MUTEX_INITIALIZER;
//thread task
task_arg_t *task_arg;



//
pthread_mutex_t mutex_lock= PTHREAD_MUTEX_INITIALIZER; 

int main(void) {


    if(init_proxy()!=STAT_OK){
        LOG(ERROR, "proxy init fail");
    }

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
    listen(server_fd, 4096);

    // epoll 인스턴스 생성
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("Epoll creation failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    //thread pool 생성 
    pthread_t thread;
    thread_cond = (thread_cond_t *)malloc(sizeof(thread_cond_t)*MAX_THREAD_POOL);
    task_arg = (task_arg_t *)malloc(sizeof(task_arg_t)*MAX_THREAD_POOL);
    for(int i=0;i<MAX_THREAD_POOL;i++){
        thread_cond[i].cond = (pthread_cond_t *)malloc(sizeof(pthread_cond_t));
        pthread_cond_init(thread_cond[i].cond, NULL);
        thread_cond[i].busy = 0;
    }
    for(int i=0;i<MAX_THREAD_POOL;i++){
        pthread_mutex_lock(&async_mutex); 
        if(pthread_create(&thread, NULL, thread_func, (void *)&i) < 0){
            LOG(ERROR, "thread create error");
        }
        pthread_cond_wait(&async_cond, &async_mutex);
        pthread_mutex_unlock(&async_mutex);
    }


    // 서버 소켓을 epoll에 등록
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN|EPOLLRDHUP;
    ev.data.fd = server_fd;
    pthread_mutex_lock(&mutex_lock); 
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("Epoll control failed");
        close(server_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
    pthread_mutex_unlock(&mutex_lock); 
    while (1) {
        struct epoll_event ev;
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
                    LOG(INFO, "new accept client fd[%d]",client_fd);
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
                    task->state = STATE_CLIENT_READ;
                    task->before_state = STATE_INITIAL_READ;
                    task->auth = false;
                    ev.events = EPOLLIN|EPOLLRDHUP;
                    ev.data.ptr = task;
                    pthread_mutex_lock(&mutex_lock); 
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    pthread_mutex_unlock(&mutex_lock); 
                }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; // 안전 검사
                // if(task->state == STATE_INITIAL_READ){
                    
                //     int ret = initial_read(task);
                //     if(ret == STAT_OK){
                //         LOG(INFO,  ">> STATE_INITIAL_READ c[%d] r[%d] event_count[%d]<<", task->client_fd, task->remote_fd, event_count);
                //     }
                //     else if(ret == STAT_FAIL){
                //         LOG(INFO, "STATE_INITIAL_READ FAIL");
                //         pthread_mutex_lock(&mutex_lock); 
                //         epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                //         pthread_mutex_unlock(&mutex_lock); 
                //         close(task->client_fd);
                //     }
                //     else{
                //         char strTmp[MAX_BUFFER_SIZE] = {0,};
                //         ret = recv(task->client_fd, strTmp, MAX_BUFFER_SIZE, 0);
                //         LOG(INFO, "STATE_INITIAL_READ read buf resul[%d]",ret);
                //         continue;
                //     }
                // }
                if (task->state == STATE_CLIENT_READ) {
                    if (events[i].events & EPOLLRDHUP) {
                        printf("Client disconnected (EPOLLRDHUP)\n");
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                        close(task->client_fd);
                    }
                    int result = 0;
                    char strTmp[MAX_BUFFER_SIZE] = {0,};
                    result = recv(task->client_fd, strTmp, MAX_BUFFER_SIZE, MSG_PEEK);
                    if(result<=0){ 
                        if(errno == EAGAIN || errno == EWOULDBLOCK)
                            continue;
                        else{
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                            close(task->client_fd);
                            // free(task);
                        }
                    }
                    LOG(INFO,  ">> STATE_CLIENT_READ c[%d] r[%d] event_count[%d]<<",task->client_fd,task->remote_fd, event_count);
                    int ret = client_read(task, epoll_fd, &ev);    
                } 
                else if (task->state == STATE_CLIENT_WRITE) 
                {
                    LOG(INFO,  ">> STATE_CLIENT_WRITE c[%d] r[%d] event_count[%d]<<", task->client_fd, task->remote_fd, event_count);
                    int ret = client_write(task, epoll_fd, &ev);
                }
                else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    // recv 값 유효성 검사해서 유효하지 못한 응답일 경우 소켓 닫는 로직 필요
                    int result = 0;
                    char strTmp[MAX_BUFFER_SIZE] = {0,};
                    result = recv(task->remote_fd, strTmp, MAX_BUFFER_SIZE, MSG_PEEK);
                    if(result<=0)
                        continue;
                    // LOG(INFO,  ">> STATE_REMOTE_READ c[%d] r[%d] event_count[%d]<<", task->client_fd, task->remote_fd,event_count);
#ifdef MULTI_THREAD

                    for(int i=0;i<MAX_THREAD_POOL;i++){
                        if(!thread_cond[i].busy){
                            memset(&task_arg[i], 0, sizeof(task_arg_t));
                            task_arg[i].epoll_fd = epoll_fd;
                            task_arg[i].ev = &ev;
                            task_arg[i].func = remote_read_process;
                            task_arg[i].task = (task_t*)calloc(1,sizeof(task_t));
                            memcpy(task_arg[i].task, task, sizeof(task_t));
                            thread_cond[i].busy=1;
                            LOG(INFO, "Thread [%d] IN", i);
                            pthread_cond_signal(thread_cond[i].cond);
                            break;
                        }
                        else{
                            if(i==MAX_THREAD_POOL-1){
                                LOG(INFO, "all thread is busy");
                                continue;
                            }
                        }
                    }
                    pthread_mutex_lock(&mutex_lock); 
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                    pthread_mutex_unlock(&mutex_lock); 
#else
                    int ret = remote_read(task, epoll_fd, &ev);
#endif

                } 
                else if (task->state == STATE_REMOTE_WRITE) {
                    LOG(INFO,  ">> STATE_REMOTE_WRITE c[%d] r[%d] event_count[%d]<<", task->client_fd, task->remote_fd,event_count);
                    int ret = remote_write(task, epoll_fd, &ev);  
                } 
                else if (task->state == STATE_CLIENT_PROXY_SSL_CONN)
                {
                    LOG(INFO,  ">> STATE_CLIENT_PROXY_SSL_CONN c[%d] r[%d] event_count[%d]<<", task->client_fd, task->remote_fd,event_count);
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