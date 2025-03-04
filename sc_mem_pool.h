#ifndef SC_MEM_POOL
#define SC_MEM_POOL
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_BUFFER_SIZE 4096
#define SC_POOL_SIZE 16384

typedef struct sc_pool_s {
    void *pool;
    size_t pool_size;
    size_t used;
    struct sc_pool_s *next;
} sc_pool_t;

sc_pool_t *sc_create_pool(size_t size);
void *sc_palloc(sc_pool_t *pool, size_t size);
void sc_destroy_pool(sc_pool_t *pool);

#endif