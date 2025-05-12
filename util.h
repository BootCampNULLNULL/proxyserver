#ifndef UTIL_H
#define UTIL_H
#include <time.h>
#include "uthash.h"
int init_proxy();
int set_current_time(time_t *cur_time);
int check_valid_time(time_t *start_time);
void daemonize();
// 해시 테이블 엔트리 구조체
typedef struct {
    char key[50];   // Key (문자열)
    char value[50]; // Value (문자열)
    UT_hash_handle hh;
} HashEntry;
base64_decode(const char *in, unsigned char *out);
#endif