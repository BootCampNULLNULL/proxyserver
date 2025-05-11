#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include "uthash.h"  // uthash 헤더 포함
#include "config_parser.h"
#include "errcode.h"
#include "auth.h"
#include "util.h"

extern pthread_mutex_t auth_lock;

static HashEntry *ip_auth_map = NULL;


static int config_count = 0;

// 설정값 저장 함수
void set_auth(const char *key, const char *value) {
    pthread_mutex_lock(&auth_lock);
    HashEntry *entry;
    HASH_FIND_STR(ip_auth_map, key, entry);
    if (entry) {
        pthread_mutex_unlock(&auth_lock);
        return;
    } else {
        // Key-Value 추가
        entry = (HashEntry *)malloc(sizeof(HashEntry));
        strcpy(entry->key, key);
        strcpy(entry->value, value);
        HASH_ADD_STR(ip_auth_map, key, entry);
    }
    pthread_mutex_unlock(&auth_lock);
}

// 설정값 가져오기 함수
const char *get_auth(const char *key) {
    pthread_mutex_lock(&auth_lock);
    HashEntry *entry;
    HASH_FIND_STR(ip_auth_map, key, entry);
    if (entry) {
        pthread_mutex_unlock(&auth_lock);
        return entry->value;
    } 
    pthread_mutex_unlock(&auth_lock);
    return NULL;
}