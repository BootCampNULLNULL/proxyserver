#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE
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
#include <signal.h>
#include <sched.h> 

#include "http.h"
#include "ssl_conn.h"
#include "client_side.h"
#include "net.h"
#include "errcode.h"
#include "log.h"
#include "config_parser.h"
#include "util.h"
#include "worker.h"
#include "db_conn.h"
#include "select_user.h"

#define NUM_CPU_CORES 4

extern thread_cond_t *thread_cond;
extern pthread_mutex_t cond_lock;
extern pthread_mutex_t mutex_lock; 
extern pthread_cond_t async_cond;
extern pthread_mutex_t async_mutex;
extern task_arg_t *task_arg;

extern pthread_mutex_t log_lock; 

extern int serverport;
extern SQLHDBC dbc;
//각 스레드 별 Thread Local Storage(TLS) 이용
// __thread int thread_local_var = 0;

void bind_thread_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void *worker_func(void *data)
{
    int th_idx = *((int*)data);

    bind_thread_to_core(th_idx % NUM_CPU_CORES);

    // 쓰레드 동기화용 조건변수
    pthread_mutex_lock(&async_mutex);
    pthread_cond_signal(&async_cond);
    pthread_mutex_unlock(&async_mutex);
     
    LOG(DEBUG, "Thread[%d] create ", th_idx);
    

    
    set_tls_db_context(dbc);
    

    int server_fd;
    struct sockaddr_in seraddr;

// 서버 소켓 생성 및 설정
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    set_nonblocking(server_fd);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    seraddr.sin_port = htons(serverport);

    if (bind(server_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
        LOG(ERROR,"Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    listen(server_fd, 4096);

    // epoll 인스턴스 생성
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        LOG(ERROR,"Epoll creation failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 서버 소켓을 epoll에 등록
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN|EPOLLRDHUP;
    ev.data.fd = server_fd;
    
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        LOG(ERROR,"Epoll control failed");
        close(server_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }
    
    

    while (1) {
        int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (event_count == -1) {
            if (errno == EINTR) continue; // 신호로 인한 중단은 무시
            LOG(ERROR,"Epoll wait failed");
            break;
        }
        for (int i = 0; i < event_count; i++) {
            struct epoll_event ev;
            if (events[i].data.fd == server_fd) {
                // 새 클라이언트 연결 처리
                // while(1) {
                    struct sockaddr_in cliaddr;
                    socklen_t len = sizeof(cliaddr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                    
                    LOG(INFO, "new accept client fd[%d]",client_fd);
                    LOG(ERROR, "th_idx[%d] Work!", th_idx);
                    if(client_fd < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK) {
                            // 모든 연결이 처리됨
                            break;
                        } else {
                            LOG(ERROR,"Accept failed");
                            break;
                        }
                    }
                    set_nonblocking(client_fd);

                    task_t* task = (task_t*)malloc(sizeof(task_t));
                    //debugging 용도
                    task->client_port = ntohs(cliaddr.sin_port);
                    task->client_fd = (int*)malloc(sizeof(int));
                    *task->client_fd = client_fd;
                    task->client_side_https = false;
                    task->client_ssl = NULL;
                    task->client_ctx = NULL;
                    task->remote_fd =  (int*)malloc(sizeof(int));
                    *task->remote_fd = -1;
                    task->remote_ctx = NULL;
                    task->remote_ssl = NULL;
                    task->remote_side_https = false;
                    task->buffer_len = 0;
                    task->state = STATE_CLIENT_READ;
                    task->before_state = STATE_INITIAL_READ;
                    task->auth = false;
                    task->user_id = NULL;
                    ev.events = EPOLLIN|EPOLLRDHUP|EPOLLONESHOT;
                    ev.data.ptr = task;
                    
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    // thread_local_var = 1;
                    
                // }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; 
                if (task->state == STATE_CLIENT_READ) {
                    if (events[i].events &  (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                        if(events[i].events & EPOLLERR)
                            LOG(INFO, "Client disconnected EPOLLERR");
                        else if(events[i].events & EPOLLHUP)
                            LOG(INFO, "Client disconnected EPOLLHUP");
                        else if(events[i].events & EPOLLRDHUP)
                            LOG(INFO, "Client disconnected EPOLLRDHUP");
                        
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                        if(*task->remote_fd != -1){
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                        }
                        release(task);
                        continue;
                    }
                    int result = 0;
                    char strTmp[MAX_BUFFER_SIZE] = {0,};
                    result = recv(*task->client_fd, strTmp, MAX_BUFFER_SIZE, MSG_PEEK);
                    if(result<=0){ 
                        if(errno == EAGAIN || errno == EWOULDBLOCK)
                            continue;
                        else{
                            LOG(ERROR, "client read error[%s] c[%d] r[%d] event_count[%d]  client port[%d]<<", strerror(errno),*task->client_fd,*task->remote_fd, event_count,  task->client_port);
                            
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                            if(*task->remote_fd != -1){
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                            }
                            release(task);
                            continue;
                        }
                    }
                     
                    LOG(INFO,  ">> STATE_CLIENT_READ c[%d] r[%d] event_count[%d]  client port[%d]<<",*task->client_fd,*task->remote_fd, event_count,  task->client_port);
                     
                    int ret = client_read(task, epoll_fd, &ev);
                } 
                else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    int ret = 0;
                    int error = 0;
                    socklen_t len = sizeof(error);

                    if (events[i].events &  (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                        LOG(INFO, "Remote disconnected (EPOLLERR | EPOLLHUP | EPOLLRDHUP)");
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                        if(*task->client_fd != -1){
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                        }
                        release(task);
                        continue;
                    }

                    ret = getsockopt(*task->client_fd, SOL_SOCKET, SO_ERROR, &error, &len);
                    if (!(ret==0 && error==0)) {
                        // 소켓 비정상인 경우
                        LOG(INFO, "Client socket error");
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->remote_fd, NULL);
                        if(*task->client_fd != -1){
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, *task->client_fd, NULL);
                        }
                        release(task);
                        continue;
                    }
                     
                    LOG(INFO,  ">> STATE_REMOTE_READ c[%d] r[%d] event_count[%d]  client port[%d]<<", *task->client_fd, *task->remote_fd,event_count,  task->client_port);
                    
                    ret = remote_read(task, epoll_fd, &ev);

                } 
                else if (task->state == STATE_CLIENT_PROXY_SSL_CONN)
                {
                     
                    LOG(INFO,  ">> STATE_CLIENT_PROXY_SSL_CONN c[%d] r[%d] event_count[%d]  client port[%d]<<", *task->client_fd, *task->remote_fd,event_count,  task->client_port);
                     
                    int ret = client_proxy_ssl_conn(task, epoll_fd, &ev);
                }
                
            }
        }
    }
    close(server_fd);
    close(epoll_fd);
    
    return 0;
}

 



