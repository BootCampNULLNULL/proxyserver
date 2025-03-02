#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>

typedef void(*task_func_t)(void *);

typedef struct
{
    int fd;
    task_func_t func;
    void *arg;
}task_event_t;

static int g_epoll_fd = -1;

void PostTask(task_func_t func,void *arg)
{
    int efd = eventfd(0,EFD_NONBLOCK);
    if(efd < 0)
    {
        perror("eventfd");
        exit(EXIT_FAILURE);
    }

    task_event_t *te = malloc(sizeof(task_event_t));
    if(!te)
    {
        perror("mlloc");
        close(efd);
        exit(EXIT_FAILURE);
    }
    te->fd = efd;
    te->func = func;
    te->arg = arg;
// epoll_event 설정: EPOLLIN 이벤트,edge_triggered
    struct epoll_event ev;
    ev.events = EPOLLIN|EPOLLET;
    ev.data.ptr = te;
    if(epoll_ctl(g_epoll_fd,EPOLL_CTL_ADD,efd,&ev)< 0)
    {
        perror("epoll_ctl ADD");
        free(te);
        close(efd);
        exit(EXIT_FAILURE);
    }

    uint64_t one = 1;
    if(write(efd,&one,sizeof(one))!= sizeof(one))
    {
        perror("write eventfd");
        exit(EXIT_FAILURE);
    }
}

void *WorkerThread(void * arg)
{
    struct epoll_event events[10];
    while(1)
    {
        int n = epoll_wait(g_epoll_fd,events,10,-1);
        if(n<0)
        {
            if(errno == EINTR)
                continue;
            perror("epoll_wait");
            break;
        }
        for(int i=0;i<n;i++)
        {
            task_event_t *te = (task_event_t *)events[i].data.ptr;
            if(!te)
                continue;
            if(epoll_ctl(g_epoll_fd,EPOLL_CTL_DEL,te->fd,NULL)<0)
                perror("epoll_ctl DEL");
            //eventfd의 카운터 값을 읽어 리셋
            uint64_t val;
            if(read(te->fd,&val,sizeof(val)) != sizeof(val))
                perror("read eventfd");
            
            te->func(te->arg);
            close(te->fd);
            free(te);
        }
    }
    return NULL;
}

void sample_task(void *arg)
{
    char *msg=(char*)arg;
    printf("Task executed: %s\n",msg);
}

void sample_task2(void *arg)
{
    int *val = (int*)arg;
    printf("val = %d\n",val);
}

#define THREAD_COUNT 4

int main()
{
    g_epoll_fd = epoll_create1(0);
    if(g_epoll_fd < 0)
    {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    pthread_t threads[THREAD_COUNT];
    for(int i=0;i<THREAD_COUNT;i++)
    {
        if(pthread_create(&threads[i],NULL,WorkerThread,NULL) != 0)
        {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }
    int val1 = 15;
    PostTask(sample_task,"Hello, World!");
    PostTask(sample_task2,(void*)val1);

    sleep(1);

    for(int i=0;i<THREAD_COUNT;i++)
    {
        pthread_cancel(threads[i]);
        pthread_join(threads[i],NULL);
    }
    close(g_epoll_fd);
    return 0;
}