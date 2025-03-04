#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROXY_BUFFER_SIZE 4096  // 첫 번째 버퍼 크기
#define PROXY_BUFFER_EXTRA_SIZE 8192 // 추가 버퍼 크기
#define NGX_POOL_SIZE 16384  // 작은 크기로 설정하여 추가 풀 생성 테스트
#define EXTRA_BUFFER_INIT_SIZE 4  // 초기 추가 버퍼 배열 크기

// 요청별 메모리 풀 구조체
typedef struct ngx_pool_s {
    void *pool;  // 메모리 풀의 시작 주소
    size_t pool_size; // 전체 메모리 풀 크기
    size_t used;  // 현재 사용 중인 메모리 크기
    struct ngx_pool_s* next;
} ngx_pool_t;

// 요청 구조체
typedef struct {
    ngx_pool_t *pool;
    char *buffer;  // 첫 번째 버퍼
    char **extra_buffers; // 추가 버퍼 배열 (동적 할당)
    int extra_buffer_count; // 현재 할당된 추가 버퍼 개수
    int extra_buffer_capacity; // 추가 버퍼 배열의 현재 용량
} ngx_http_request_t;

// 메모리 풀 생성
ngx_pool_t *ngx_create_pool(size_t size) {
    ngx_pool_t *pool = malloc(sizeof(ngx_pool_t));
    pool->pool = malloc(size);
    pool->pool_size = size;
    pool->used = 0;
    pool->next = NULL;
    return pool;
}

// 메모리 풀에서 메모리 할당
void *ngx_palloc(ngx_pool_t *pool, size_t size) {
    while (pool) {
        if (pool->used + size <= pool->pool_size) {
            void *ptr = (char *)pool->pool + pool->used;
            pool->used += size;
            return ptr;
        }
        if (!pool->next) {
            pool->next = ngx_create_pool(NGX_POOL_SIZE);
            printf("🔹 추가 메모리 풀 할당 (크기: %ld 바이트)\n", NGX_POOL_SIZE);
        }
        pool = pool->next;
    }
    return NULL;
}

// 요청 생성
ngx_http_request_t *ngx_create_request() {
    ngx_http_request_t *r = malloc(sizeof(ngx_http_request_t));
    r->pool = ngx_create_pool(NGX_POOL_SIZE);
    r->buffer = ngx_palloc(r->pool, PROXY_BUFFER_SIZE);
    r->extra_buffers = malloc(EXTRA_BUFFER_INIT_SIZE * sizeof(char *));
    r->extra_buffer_count = 0;
    r->extra_buffer_capacity = EXTRA_BUFFER_INIT_SIZE;
    return r;
}

// 추가 버퍼 할당
void ngx_allocate_extra_buffer(ngx_http_request_t *r) {
    if (r->extra_buffer_count >= r->extra_buffer_capacity) {
        r->extra_buffer_capacity *= 2;
        r->extra_buffers = realloc(r->extra_buffers, r->extra_buffer_capacity * sizeof(char *));
    }
    r->extra_buffers[r->extra_buffer_count] = ngx_palloc(r->pool, PROXY_BUFFER_EXTRA_SIZE);
    printf("추가 버퍼 %d 할당 완료 (크기: %d 바이트)\n", r->extra_buffer_count, PROXY_BUFFER_EXTRA_SIZE);
    r->extra_buffer_count++;
}

// 메모리 풀 해제
void ngx_destroy_pool(ngx_pool_t *pool) {
    while (pool) {
        ngx_pool_t *next = pool->next;
        free(pool->pool);
        free(pool);
        pool = next;
    }
}

// 요청 해제
void ngx_destroy_request(ngx_http_request_t *r) {
    free(r->extra_buffers);  // 포인터 배열 자체 해제
    ngx_destroy_pool(r->pool);  // 메모리 풀 해제
    free(r);  // 요청 구조체 해제
}

int main() {
    ngx_http_request_t *req = ngx_create_request();
    if (req->buffer) {
        printf("첫 번째 버퍼 할당 성공 (크기: %d 바이트)\n", PROXY_BUFFER_SIZE);
    }

    // 메모리 풀 초과 테스트 (작은 NGX_POOL_SIZE 설정으로 강제 발생)
    for (int i = 0; i < 10; i++) {
        ngx_allocate_extra_buffer(req);
    }

    ngx_destroy_request(req);
    printf("요청 종료, 메모리 해제 완료!\n");

    return 0;
}