#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "uthash.h"  // uthash 헤더 포함
#include "config_parser.h"
#include "errcode.h"


// 해시 테이블 엔트리 구조체
typedef struct {
    char key[50];   // Key (문자열)
    char value[50]; // Value (문자열)
    UT_hash_handle hh;
} HashEntry;

static HashEntry *config_map = NULL;


static int config_count = 0;

// 설정값 저장 함수
void set_config_value(const char *key, const char *value) {
    HashEntry *entry;
    HASH_FIND_STR(config_map, key, entry);
    if (entry) {
        printf("ERROR Key exists! Value: %s\n", entry->value);
        return;
    } else {
        // Key-Value 추가
        entry = (HashEntry *)malloc(sizeof(HashEntry));
        strcpy(entry->key, key);
        strcpy(entry->value, value);
        HASH_ADD_STR(config_map, key, entry);
    }
}

// 설정값 가져오기 함수
const char *get_config_string(const char *key) {
    HashEntry *entry;
    HASH_FIND_STR(config_map, key, entry);
    if (entry) {
        return entry->value;
    } 
    return NULL;
}

int get_config_int(const char *key) {
    HashEntry *entry;
    HASH_FIND_STR(config_map, key, entry);
    if (entry) {
        return atoi(entry->value);
    } 
    return NULL;
}

// 문자열 앞뒤 공백 제거 함수
char *trim(char *str) {
    char *end;

    // 앞쪽 공백 제거 (왼쪽에서 오른쪽으로 이동)
    while (isspace((unsigned char)*str)) str++;

    // 문자열이 비어 있으면 리턴
    if (*str == 0) return str;

    // 뒤쪽 공백 제거 (오른쪽에서 왼쪽으로 이동)
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    // 문자열 끝을 NULL 문자로 설정
    *(end + 1) = '\0';

    return str;
}


// 설정 파일 로드 함수
int load_config() {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        perror("Failed to open config file");
        return -1;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), file)) {
        char *key, *value;

        // 개행 문자 제거
        line[strcspn(line, "\r\n")] = 0;

        // 주석(#) 또는 빈 줄 무시
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        // key=value 형태로 파싱
        key = strtok(line, "=");
        value = strtok(NULL, "=");

        if (key && value) {
            // 앞뒤 공백 제거
            key = trim(key);
            value = trim(value);
            set_config_value(key, value);
        }
    }

    fclose(file);
    return STAT_OK;
}

// 설정값 출력 함수
void print_config() {
    printf("Configurations:\n");
    HashEntry *entry, *tmp;
    HASH_ITER(hh, config_map, entry, tmp) {
        printf("%s = %s\n", entry->key, entry->value);
    }
}

