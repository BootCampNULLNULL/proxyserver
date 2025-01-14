#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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


// 문자열의 공백을 제거하는 유틸리티 함수
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
    char* host = find_Host_field(request->header);
    if (host) {
        request->host = strdup(host);
        request->port = find_port(host);
        free(host);
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

// int main() {
//     char raw_request[] =
//         "GET /index.html?name=test&age=25 HTTP/1.1\r\n"
//         "Host: www.example.com:443\r\n"
//         "User-Agent: curl/7.68.0\r\n"
//         "Accept: */*\r\n"
//         "\r\n";

//     HTTPRequest* req = read_request(raw_request);

//     // 요청 라인 출력
//     printf("Method: %s\n", req->method);
//     printf("Path: %s\n", req->path);
//     printf("HTTP Version: 1.%d\n", req->protocol_minor_version);

//     // 쿼리 파라미터 출력
//     HTTPQueryParam *query = req->query;
//     printf("Query Parameters:\n");
//     while (query) {
//         printf("  %s: %s\n", query->name, query->value);
//         query = query->next;
//     }

//     // 헤더 출력
//     HTTPHeaderField *header = req->header;
//     printf("Headers:\n");
//     while (header) {
//         printf("  %s: %s\n", header->name, header->value);
//         header = header->next;
//     }

//     // Host 필드 값 추출
//     if (req->host) {
//         printf("Host: %s\n", req->host); // 호스트 이름 출력
//         printf("Port: %d\n", req->port); // 포트 출력
//     } else {
//         printf("Host 필드가 없습니다.\n");
//     }

//     // 메모리 해제
//     free_request(req);

//     return 0;
// }
