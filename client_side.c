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
#include <signal.h>
#include <sqlite3.h>
#include <sql.h>
#include <sqlext.h>
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
//전역 변수
EVP_PKEY *ca_key=NULL;
X509 *ca_cert=NULL;
int serverport;
int timeout = 0;
EVP_PKEY *ssl_key=NULL;

SQLHENV env;
SQLHDBC dbc;

pthread_key_t tls_key;
// 각 스레드 별 Thread Local Storage(TLS) 이용
void init_tls_db_context() {
    pthread_key_create(&tls_key, free); 
}

void set_tls_db_context(SQLHDBC dbc) {
    SQLHSTMT stmt;
    stmt = NULL;
    int ret = SQLAllocHandle(SQL_HANDLE_STMT, dbc, &stmt);
    if (ret != SQL_SUCCESS && ret != SQL_SUCCESS_WITH_INFO) {
        LOG(ERROR, "SQLAllocHandle failed: ret = %d", ret);
        return;
    }
    pthread_setspecific(tls_key, stmt);
}

SQLHSTMT get_tls_db_context() {
    return (SQLHSTMT)pthread_getspecific(tls_key);
}


//thread 수 
#define MAX_THREAD_POOL 5
//각 thread를 위한 동기화 조건 변수
thread_cond_t *thread_cond;
//각 thread critical section 지정
pthread_mutex_t cond_lock= PTHREAD_MUTEX_INITIALIZER; 
//thread 생성 시 동기화 조건 변수
pthread_cond_t async_cond = PTHREAD_COND_INITIALIZER;
//thread 생성 시 동기화용
pthread_mutex_t async_mutex = PTHREAD_MUTEX_INITIALIZER;
// ip_auth hash map 동기화용
pthread_mutex_t auth_lock= PTHREAD_MUTEX_INITIALIZER;
//thread task
task_arg_t *task_arg;



//
pthread_mutex_t mutex_lock= PTHREAD_MUTEX_INITIALIZER; 

pthread_mutex_t log_lock= PTHREAD_MUTEX_INITIALIZER; 

int main(void) {


    if(init_proxy()!=STAT_OK){
         
        LOG(ERROR, "proxy init fail");
         
    }

    if (!ca_key || !ca_cert) {
        LOG(ERROR, "Failed to load CA key or certificate\n");
        exit(EXIT_FAILURE);
    }

    init_tls_db_context();

    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN); 

    daemonize();

        //thread pool 생성 
    pthread_t thread;
    for(int i=0;i<MAX_THREAD_POOL;i++){
        pthread_mutex_lock(&async_mutex); 
        int* idx = (int*)malloc(sizeof(int));
        *idx = i;
        if(pthread_create(&thread, NULL, worker_func, (void *)idx) < 0){
             
            LOG(ERROR, "thread create error");
             
        }
        pthread_cond_wait(&async_cond, &async_mutex);
        pthread_mutex_unlock(&async_mutex);
    }
    while(1){
        sleep(3600);
    }

    
    return 0;
}
