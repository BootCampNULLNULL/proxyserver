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
void parse_query_params(char *query_string, HTTPRequest *request) {
    char *param = strtok(query_string, "&");
    while (param) {
        char *equal = strchr(param, '=');
        if (!equal) {
            fprintf(stderr, "잘못된 쿼리 파라미터: %s\n", param);
            exit(EXIT_FAILURE);
        }

        *equal = '\0';
        char *name = trim_whitespace(param);
        char *value = trim_whitespace(equal + 1);

        HTTPQueryParam *query_param = (HTTPQueryParam*)malloc(sizeof(HTTPQueryParam));
        query_param->name = strdup(name);
        query_param->value = strdup(value);
        query_param->next = NULL;

        if (!request->query) {
            request->query = query_param;
        } else {
            HTTPQueryParam *current = request->query;
            while (current->next) current = current->next;
            current->next = query_param;
        }

        param = strtok(NULL, "&");
    }
}

// 요청 라인을 파싱하는 함수
void read_request_line(const char *buffer, HTTPRequest *request) {
    char *line = strdup(buffer);
    char *method = strtok(line, " ");
    char *path_with_query = strtok(NULL, " ");
    char *version = strtok(NULL, " ");

    if (!method || !path_with_query || !version) {
        free(line);
        fprintf(stderr, "잘못된 요청 라인\n");
        exit(EXIT_FAILURE);
    }

    request->method = strdup(method);

    // 쿼리 문자열 분리
    char *query_start = strchr(path_with_query, '?');
    if (query_start) {
        *query_start = '\0';
        request->path = strdup(path_with_query);
        parse_query_params(query_start + 1, request);
    } else {
        request->path = strdup(path_with_query);
    }

    if (strncmp(version, "HTTP/1.", 7) == 0) {
        request->protocol_minor_version = version[7] - '0';
    } else {
        fprintf(stderr, "지원되지 않는 HTTP 버전\n");
        free(line);
        exit(EXIT_FAILURE);
    }

    free(line);
}

// 헤더 필드를 파싱하는 함수
void read_header_field(const char *buffer, HTTPRequest *request) {
    char *line = strdup(buffer);
    char *colon = strchr(line, ':');

    if (!colon) {
        free(line);
        fprintf(stderr, "잘못된 헤더 필드\n");
        exit(EXIT_FAILURE);
    }

    *colon = '\0';
    char *name = trim_whitespace(line);
    char *value = trim_whitespace(colon + 1);

    HTTPHeaderField *field = (HTTPHeaderField*)malloc(sizeof(HTTPHeaderField));
    field->name = strdup(name);
    field->value = strdup(value);
    field->next = NULL;

    if (!request->header) {
        request->header = field;
    } else {
        HTTPHeaderField *current = request->header;
        while (current->next) current = current->next;
        current->next = field;
    }

    free(line);
}

// HTTP 요청 데이터를 파싱하는 메인 함수
HTTPRequest *read_request(const char *buffer) {
    HTTPRequest *request = (HTTPRequest*)calloc(1, sizeof(HTTPRequest));

    const char *current = buffer;
    char line[MAX_LINE_SIZE];

    // 요청 라인 파싱
    const char *line_end = strstr(current, "\r\n");
    if (!line_end) {
        fprintf(stderr, "잘못된 HTTP 요청\n");
        exit(EXIT_FAILURE);
    }
    size_t line_length = line_end - current;
    strncpy(line, current, line_length);
    line[line_length] = '\0';
    read_request_line(line, request);
    current = line_end + 2;

    // 헤더 파싱
    while ((line_end = strstr(current, "\r\n")) && line_end != current) {
        line_length = line_end - current;
        strncpy(line, current, line_length);
        line[line_length] = '\0';
        read_header_field(line, request);
        current = line_end + 2;
    }

    // Host 필드와 포트 설정
    request->host = find_Host_field(request->header);
    if (request->host) {
        request->port = find_port(request->host);
    } else {
        request->host = NULL;
        request->port = 0; // Host가 없을 경우
    }

    // 빈 줄을 건너뜀
    if (line_end == current) {
        current += 2;
    }

    // 본문(body)을 파싱
    if (*current != '\0') {
        request->body = strdup(current);
        request->length = strlen(request->body);
    }

    return request;
}

char* find_Host_field(HTTPHeaderField* head) {
    while (head) {
        if (strcmp(head->name, "Host") == 0) {
            return strdup(head->value);
        }
        head = head->next;
    }
    return NULL; // Host 필드가 없을 경우
}

// Host 값에서 포트를 추출하며, 호스트 문자열을 수정하는 함수
int find_port(char* host) {
    char* port_s = strstr(host, ":");
    if (port_s) {
        *port_s = '\0'; // ':'를 null로 바꿔 호스트와 포트를 분리
        return atoi(port_s + 1); // ':' 뒤의 포트를 정수로 변환하여 반환
    }
    return -1;
}

// HTTPRequest 구조체를 해제하는 함수
void free_request(HTTPRequest *request) {
    if(!request || request == 0x00 || request==NULL)
        return;
    if (request->method) free(request->method);
    if (request->path) free(request->path);
    if (request->host) free(request->host);

    HTTPQueryParam *query = request->query;
    while (query) {
        HTTPQueryParam *next = query->next;
        free(query->name);
        free(query->value);
        free(query);
        query = next;
    }

    HTTPHeaderField *current = request->header;
    while (current) {
        HTTPHeaderField *next = current->next;
        free(current->name);
        free(current->value);
        free(current);
        current = next;
    }

    if (request->body) free(request->body);
    free(request);
}

int get_IP(char* ip_str, const char* hostname, int port) {
    struct addrinfo hints, *res, *p;
    //char ip_str[INET6_ADDRSTRLEN];  // IPv6도 포함한 크기

    // hints 초기화
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;       // IPv4 또는 IPv6 허용
    hints.ai_socktype = SOCK_STREAM;  // TCP 소켓

    char s_port[6];
    snprintf(s_port, sizeof(s_port), "%d", port);
    // getaddrinfo 호출
    int status = getaddrinfo(hostname, "80", &hints, &res);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        return 1;
    }

    //printf("IP addresses for %s:\n\n", hostname);

    void *addr;
    const char *ipver;

    // 첫 번째 노드 처리
    if (res->ai_family == AF_INET) {  // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else if (res->ai_family == AF_INET6) {  // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    } else {
        fprintf(stderr, "Unknown address family\n");
        freeaddrinfo(res);
        return 1;
    }

    // IP 주소를 문자열로 변환
    inet_ntop(res->ai_family, addr, ip_str, INET_ADDRSTRLEN);
    printf("  %s: %s\n", ipver, ip_str);

    freeaddrinfo(res);
    return 0;
}

