#ifndef SC_MEM_POOL
#define SC_MEM_POOL
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_REQUEST_BUFFER_SIZE 5120
#define MAX_RESPONSE_BUFFER_SIZE 8192
#define SC_POOL_SIZE 16384
#define DEFAULT_MEM_BLOCK_SIZE 512

// 버퍼 체인 구조체
typedef struct sc_buf_s {
    char *start;         // 버퍼 시작 위치
    char *pos;           // 현재 읽기 위치
    char *last;          // 현재까지 저장된 위치
    char *end;           // 버퍼 끝 위치
    struct sc_buf_s *next; // 다음 버퍼 포인터
} sc_buf_t;

// 메모리풀 구조체
typedef struct sc_pool_t {
    void *pool;
    size_t pool_size;
    size_t used;
    struct sc_pool_s *next;
} sc_pool_t;

sc_pool_t *sc_create_pool(size_t size);
void* sc_palloc(sc_pool_t *pool, size_t size);
sc_buf_t *sc_alloc_buffer(sc_pool_t *pool, size_t size);
void sc_destroy_pool(sc_pool_t *pool);

#endif