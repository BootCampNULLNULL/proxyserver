#include "sc_mem_pool.h"
#include "log.h"

// 메모리풀 할당
sc_pool_t *sc_create_pool(size_t size) {
    sc_pool_t *pool = malloc(sizeof(sc_pool_t));
    pool->pool = malloc(size);
    pool->pool_size = size;
    pool->used = 0;
    pool->next = NULL;
    return pool;
}

// 메모리 풀에서 메모리 할당
void *sc_palloc(sc_pool_t *pool, size_t size) {
    while (pool) {
        if (pool->used + size <= pool->pool_size) {
            void *ptr = (char *)pool->pool + pool->used;
            pool->used += size;
            return ptr;
        }
        // 메모리풀 용량 초과
        if (!pool->next) {
            pool->next = sc_create_pool(SC_POOL_SIZE);
            LOG(DEBUG, "추가 메모리 풀 할당 (크기: %ld 바이트)\n", SC_POOL_SIZE);
        }
        pool = pool->next;
    }
    return;
}

// 버퍼 체인 할당
sc_buf_t *sc_alloc_buffer(sc_pool_t *pool, size_t size) {
    sc_buf_t *buf = sc_palloc(pool, sizeof(sc_buf_t));
    buf->start = sc_palloc(pool, size);
    buf->pos = buf->start;
    buf->last = buf->start;
    buf->end = buf->start + size;
    buf->next = NULL;
    return buf;
}

// 메모리 풀 해제
void sc_destroy_pool(sc_pool_t *pool) {
    while (pool) {
        sc_pool_t *next = pool->next;
        free(pool->pool);
        free(pool);
        pool = next;
    }
}