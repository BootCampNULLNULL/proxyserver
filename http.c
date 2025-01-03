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

#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define protocol_minor_version
#define LINE_BUF_SIZE 4096

#define str3_cmp(m, c0, c1, c2) m[0] == c0 && m[1] == c1 && m[2] == c2
#define str4_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3
#define str7_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4 && m[5] == c5 && m[6] == c6

#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 2048
#define MAX_PROTOCOL_SIZE 16
#define MAX_HEADER_SIZE 8192

typedef struct {
    char method[MAX_METHOD_SIZE];
    char uri[MAX_URI_SIZE];
    char protocol[MAX_PROTOCOL_SIZE];
    char headers[MAX_HEADER_SIZE];
} HttpRequest;

// HTTP 요청 파싱 함수
int parse_http_request(char *request, HttpRequest *http_request) {
    if (!request || !http_request) return -1;

    char *line = request;

    // 요청 라인 파싱
    char *newline = strstr(line, "\r\n");
    if (!newline) return -1;

    *newline = '\0'; // 요청 라인의 끝에 NULL 삽입
    if (sscanf(line, "%15s %2047s %15s", http_request->method, http_request->uri, http_request->protocol) != 3) {
        return -1;
    }

    // 헤더 파싱
    line = newline + 2; // 헤더 시작 위치로 이동
    http_request->headers[0] = '\0'; // 초기화
    while ((newline = strstr(line, "\r\n")) != NULL) {
        if (newline == line) { // 빈 줄 (헤더 끝)
            break;
        }

        *newline = '\0'; // 현재 헤더 라인 끝에 NULL 삽입
        strncat(http_request->headers, line, MAX_HEADER_SIZE - strlen(http_request->headers) - 1);
        strncat(http_request->headers, "\n", MAX_HEADER_SIZE - strlen(http_request->headers) - 1);

        line = newline + 2; // 다음 라인으로 이동
    }

    return 0;
}

// 디버깅 및 출력용
void print_http_request(const HttpRequest *http_request) {
    printf("Method: %s\n", http_request->method);
    printf("URI: %s\n", http_request->uri);
    printf("Protocol: %s\n", http_request->protocol);
    printf("Headers:\n%s\n", http_request->headers);
}

// 테스트 코드
int main() {
    char raw_request[] =
        "GET /index.html HTTP/1.1\r\n"
        "Host: www.example.com\r\n"
        "User-Agent: curl/7.68.0\r\n"
        "Accept: */*\r\n"
        "\r\n";

    HttpRequest http_request;
    if (parse_http_request(raw_request, &http_request) == 0) {
        print_http_request(&http_request);
    } else {
        printf("Failed to parse HTTP request.\n");
    }

    return 0;
}