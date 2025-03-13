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
#include "http.h"
#include "errcode.h"

char *trim_whitespace(char *str) {
    char *end;

    while (*str == ' ' || *str == '\t') str++;
    if (*str == 0) return str;

    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r')) end--;

    *(end + 1) = '\0';
    return str;
}

// 쿼리 파라미터를 파싱하는 함수
// void parse_query_params(char *query_start, size_t length, HTTPRequest *request) {
//     char *end = query_start + length;
//     char *param_start = query_start;
//     while (param_start < end) {
//         char *equal = memchr(param_start, '=', end - param_start);
//         if (!equal) break;
//         char *amp = memchr(equal, '&', end - equal);

//         HTTPQueryParam *query_param = malloc(sizeof(HTTPQueryParam));
//         query_param->name.start = param_start;
//         query_param->name.length = equal - param_start;

//         if (amp) {
//             query_param->value.start = equal + 1;
//             query_param->value.length = amp - (equal + 1);
//             param_start = amp + 1;
//         } else {
//             query_param->value.start = equal + 1;
//             query_param->value.length = end - (equal + 1);
//             param_start = end;
//         }

//         query_param->next = request->query;
//         request->query = query_param;
//     }
// }

void read_request_line(sc_buf_t *buf, HTTPRequest *request) {
    char *pos = buf->pos;  // 현재 위치 포인터
    char *end = buf->last; // 버퍼 끝 위치

    char *method_end = NULL;   // HTTP 메서드 끝 위치 (첫 번째 공백)
    char *url_end = NULL;      // 요청 URL 끝 위치 (두 번째 공백)
    char *request_line_end = NULL; // 요청 라인 끝 위치 (\r\n)

    // 한 번의 루프에서 요청 라인을 파싱
    for (; pos < end; pos++) {
        if (*pos == ' ') {
            if (!method_end) {
                method_end = pos;  // 첫 번째 공백 (메서드 끝)
            } else if (!url_end) {
                url_end = pos;  // 두 번째 공백 (URL 끝)
            }
        } else if (*pos == '\r' && (pos + 1 < end) && *(pos + 1) == '\n') {
            request_line_end = pos;  // 요청 라인의 끝 (\r\n)
            break;
        }
    }

    // HTTP 메서드 저장
    request->method.start = buf->pos;
    request->method.length = method_end - buf->pos;

    // URL 및 쿼리 문자열 저장
    char *url_start = method_end + 1;
    char *query_start = memchr(url_start, '?', url_end - url_start);

    if (query_start) {
        request->query.start = query_start;
        request->query.length = query_start - url_start;
    } else {
        request->path.start = url_start;
        request->path.length = url_end - url_start;
    }

    // HTTP 버전 확인
    if (strncmp(url_end + 1, "HTTP/1.", 7) == 0) {
        request->protocol_minor_version = url_end[8] - '0';
    }

    // 요청 라인의 끝(\r\n 이후)으로 이동
    if (request_line_end) {
        buf->pos = request_line_end + 2;
    }
}


void read_header_field(sc_buf_t *buf, size_t length, HTTPRequest *request) {
    char *colon = memchr(buf->pos, ':', length);
    if (!colon) return;

    HTTPHeaderField *field = malloc(sizeof(HTTPHeaderField));
    field->name.start = buf->pos;
    field->name.length = colon - buf->pos;

    char *value_start = colon + 1;
    while (*value_start == ' ' && (value_start - buf->pos) < length) value_start++;
    field->value.start = value_start;
    field->value.length = (buf->pos + length) - value_start;

    // 가장 마지막에 추가된 헤더가 리스트의 헤더노드가 됨
    field->next = request->header;
    request->header = field;
}

HTTPRequest *read_request(sc_buf_t *buf) {
    HTTPRequest *request = malloc(sizeof(HTTPRequest));

    read_request_line(buf, request);

    while (buf->pos < buf->last) {
        char *line_end = memchr(buf->pos, '\r', buf->last - buf->pos);
        if (!line_end || line_end == buf->pos) break;
        read_header_field(buf, line_end - buf->pos, request);
        buf->pos = line_end + 2;
    }

    buf->pos += 2;
    request->body.start = buf->pos;
    request->body.length = buf->last - buf->pos;

    parse_host_and_port(request);
    request->s_host = HTTPString_to_value(request->host);
    buf->pos = buf->start;
    return request;
}

void parse_host_and_port(HTTPRequest *request) {
    HTTPHeaderField *header = request->header;
    while (header) {
        if (header->name.length == 4 && strncasecmp(header->name.start, "Host", 4) == 0) {
            request->host.start = header->value.start;
            request->host.length = header->value.length;

            char *colon = memchr(request->host.start, ':', request->host.length);
            if (colon) {
                request->port = atoi(colon + 1);
                request->host.length = colon - request->host.start;
            } else {
                request->port = 80;
            }
            return;
        }
        header = header->next;
    }
    request->port = 80;
}

// 호출자쪽에서 사용 후 적절히 free 필요
char *HTTPString_to_value(HTTPString str) {
    if (!str.start || str.length == 0) {
        return NULL;
    }

    char *result = (char *)malloc(str.length + 1);
    if (!result) {
        perror("malloc failed");
        return NULL;
    }

    memcpy(result, str.start, str.length);
    result[str.length] = '\0';

    return result;
}

void free_request(HTTPRequest *request) {
    // HTTPQueryParam *query = request->query;
    // while (query) {
    //     HTTPQueryParam *next = query->next;
    //     free(query);
    //     query = next;
    // }

    HTTPHeaderField *header = request->header;
    while (header) {
        HTTPHeaderField *next = header->next;
        free(header);
        header = next;
    }

    if(request->s_host) free(request->s_host);
    free(request);
}