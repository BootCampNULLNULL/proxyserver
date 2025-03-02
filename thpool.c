#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <string.h>
#include "client_side.h"

#define THREAD_POOL_SIZE    4

//콜백 함수 타입 정의
typedef void(*task_func)(void *);

typedef struct task
{
    task_func func;
    void * arg;
    struct tast *next;
}task;

typedef struct task_queue
{
    task *head;
    task *tail;
    pthread_mutex_t lock;
}task_queue;

//작업 큐
task_queue work_queue = {NULL,NULL,PTHREAD_MUTEX_INITIALIZER};

int event_fd;

void PostTast(task_func func,void* arg)
{
    task *new_task = (task*)malloc(sizeof(task));
    if(!new_task)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }
    new_task->func = func;
    new_task->arg = arg;
    new_task->next = NULL;

    //작업 큐에 추가
    pthread_mutex_lock(&work_queue.lock);
    if(work_queue.tail == NULL)
        work_queue.head = work_queue.tail = new_task;
    else
    {
        work_queue.tail->next = new_task;
        work_queue.tail = new_task;
    }
    pthread_mutex_unlock(&work_queue.lock);

    //eventfd에 1을 기록하여 이벤트를 발생시킴
    uint64_t one = 1;
    write(event_fd,&one,sizeof(one));
}

task *PopTask()
{
    pthread_mutex_lock(&work_queue.lock);
    task *task = work_queue.head;
    if(task)
    {
        work_queue.head = task->next;
        if(work_queue.head == NULL)
            work_queue.tail = NULL;
    }
    pthread_mutex_unlock(&work_queue.lock);
    return task;
}

void* WorkerThreadProc(void* arg)
{
    struct epoll_event event[10];
    while(1)
    {
        int nfds = epoll_wait(epoll_fd,events,10,-1);
        if(nfds == -1)
        {
            if(errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        for(int i=0;i<nfds;i++)
        {
            if(events[i].data.fd == event_fd)
            {
                uint64_t count;
                if(read(event_fd,&count,sizeof(count)) != sizeof(count))
                    perror("read from eventfd");
                task *task;
                while((task = PopTask()) != NULL)
                {
                    task->func(task->arg);
                    free(task);
                }
            }
        }
    }
    return NULL;
}
