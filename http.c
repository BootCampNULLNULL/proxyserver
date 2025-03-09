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
void parse_query_params(char *query_start, size_t length, HTTPRequest *request) {
    char *end = query_start + length;
    char *param_start = query_start;
    while (param_start < end) {
        char *equal = memchr(param_start, '=', end - param_start);
        if (!equal) break;
        char *amp = memchr(equal, '&', end - equal);

        HTTPQueryParam *query_param = malloc(sizeof(HTTPQueryParam));
        query_param->name.start = param_start;
        query_param->name.length = equal - param_start;

        if (amp) {
            query_param->value.start = equal + 1;
            query_param->value.length = amp - (equal + 1);
            param_start = amp + 1;
        } else {
            query_param->value.start = equal + 1;
            query_param->value.length = end - (equal + 1);
            param_start = end;
        }

        query_param->next = request->query;
        request->query = query_param;
    }
}

void read_request_line(const char *buffer, HTTPRequest *request) {
    const char *space1 = strchr(buffer, ' ');
    const char *space2 = strchr(space1 + 1, ' ');

    request->method.start = (char *)buffer;
    request->method.length = space1 - buffer;

    const char *path_start = space1 + 1;
    const char *query_start = memchr(path_start, '?', space2 - path_start);

    if (query_start) {
        request->path.start = (char *)path_start;
        request->path.length = query_start - path_start;
        parse_query_params((char *)(query_start + 1), space2 - (query_start + 1), request);
    } else {
        request->path.start = (char *)path_start;
        request->path.length = space2 - path_start;
    }

    if (strncmp(space2 + 1, "HTTP/1.", 7) == 0) {
        request->protocol_minor_version = space2[8] - '0';
    } else {
        fprintf(stderr, "Unsupported HTTP version\n");
        exit(EXIT_FAILURE);
    }
}

void read_header_field(const char *line, size_t length, HTTPRequest *request) {
    const char *colon = memchr(line, ':', length);
    if (!colon) return;

    HTTPHeaderField *field = malloc(sizeof(HTTPHeaderField));
    field->name.start = (char *)line;
    field->name.length = colon - line;

    const char *value_start = colon + 1;
    while (*value_start == ' ' && (value_start - line) < length) value_start++;
    field->value.start = (char *)value_start;
    field->value.length = (line + length) - value_start;

    field->next = request->header;
    request->header = field;
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

HTTPRequest *read_request(const char *buffer) {
    HTTPRequest *request = calloc(1, sizeof(HTTPRequest));
    const char *current = buffer;

    const char *line_end = strstr(current, "\r\n");
    read_request_line(current, request);
    current = line_end + 2;

    while ((line_end = strstr(current, "\r\n")) && line_end != current) {
        read_header_field(current, line_end - current, request);
        current = line_end + 2;
    }

    current += 2;
    request->body.start = (char *)current;
    request->body.length = strlen(current);

    parse_host_and_port(request);
    request->s_host = HTTPString_to_value(request->host);

    return request;
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
    HTTPQueryParam *query = request->query;
    while (query) {
        HTTPQueryParam *next = query->next;
        free(query);
        query = next;
    }

    HTTPHeaderField *header = request->header;
    while (header) {
        HTTPHeaderField *next = header->next;
        free(header);
        header = next;
    }

    if(request->s_host) free(request->s_host);
    free(request);
}