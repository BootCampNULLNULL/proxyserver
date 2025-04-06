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
#include <time.h>
#include "util.h"
#include "errcode.h"
#include "config_parser.h"
#include "util.h"
#include "log.h"
#include "ssl_conn.h"


extern int timeout;
extern int serverport;
extern EVP_PKEY *ca_key;
extern X509 *ca_cert;
extern log_lock; 

int init_proxy()
{

    initialize_openssl();

    if(load_config()!=STAT_OK)
    {
        pthread_mutex_lock(&log_lock); 
        LOG(ERROR, "config load error");
        pthread_mutex_unlock(&log_lock); 
    }

    const char *cert_file = get_config_string("CERT_FILE");
    const char *key_file = get_config_string("KEY_FILE");
    serverport = get_config_int("SERVERPORT");
    timeout = get_config_int("CONNECT_TIME");

    int ret = 0;

    if((ret=load_private_key(key_file,&ca_key)) == ENOENT)
    {
        //키 파일 존재하지 않는 경우 생성
        pthread_mutex_lock(&log_lock); 
        LOG(INFO, "Create ca key");
        pthread_mutex_unlock(&log_lock); 
        EVP_PKEY *key = generate_rsa_key();
        if (!key) {
            pthread_mutex_lock(&log_lock); 
            LOG(ERROR, "Create key fail");
            pthread_mutex_unlock(&log_lock); 
            return STAT_FAIL;
        }
        if(save_key(key, key_file) == STAT_FAIL)
            return STAT_FAIL;
        //TO-DO 인증서 2번 load 하지 않도록 수정 필요
        if(load_private_key(key_file, &ca_key)!=STAT_OK)
            return STAT_FAIL;
        
        //키 없는 경우 키에 맞게 인증서도 새로 생성
        ca_cert = generate_cert("Root CA", ca_key, NULL, ca_key/*self-sign*/, 1/*root cert*/);
        if(save_cert(ca_cert, cert_file)!=STAT_OK)
            return STAT_FAIL;
    }
    else if(ret != STAT_OK)
    {
        return STAT_FAIL;
    }
    
    if((ret = load_certificate(cert_file, &ca_cert))==ENOENT)
    {
        //인증서 없고 키만 있는 경우
        ca_cert = generate_cert("Root CA", ca_key, NULL, ca_key/*self-sign*/, 1/*root cert*/);
        if(save_cert(ca_cert, cert_file)!=STAT_OK)
            return STAT_FAIL;
        if(load_certificate(cert_file, &ca_cert) != STAT_OK)
            return STAT_FAIL;
    }
    else if(ret!=STAT_OK)
    {
        return STAT_FAIL;
    }
    return STAT_OK;
}

/**
 * @brief 초기 시간 설정
 * 
 * @return int 
 * 성공(0), 실패(-1)
 */
// int set_current_time(time_t *cur_time){
//     struct timespec ts;
//     int result=0;
//     result = clock_gettime(CLOCK_MONOTONIC, &ts);
//     if(result==STAT_FAIL)
//         return STAT_FAIL;
//     *cur_time = ts.tv_sec;
//     return STAT_OK;
// }

/**
 * @brief 연결이 timeout 됬는지 확인
 * 
 * @return int 
 * 성공(0), 실패(-1)
 */
// int check_valid_time(time_t *start_time){
//     time_t cur_time;
//     set_current_time(&cur_time);
//     if((cur_time-*start_time)>timeout)
//         return STAT_FAIL;
//     return STAT_OK;
// }


