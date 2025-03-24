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


HTTPRequestParser *create_parser(sc_buf_t *buf) {
    HTTPRequestParser *parser = (HTTPRequestParser *)malloc(sizeof(HTTPRequestParser));
    if (!parser) return NULL;
    
    parser->request = (HTTPRequest *)malloc(sizeof(HTTPRequest));
    if (!parser->request) {
        free(parser);
        return NULL;
    }
    memset(parser->request, 0, sizeof(HTTPRequest));

    parser->cur_buf = buf;
    parser->pos = buf->pos;
    parser->last = buf->last;
    parser->state = HTTP_STATE_METHOD;

    return parser;
}

void free_parser(HTTPRequestParser *parser) {
    if (!parser) return;
    free_request(parser->request);
    free(parser);
}

HTTPParseResult parse_http_request(HTTPRequestParser *parser) {
    if (!parser || !parser->cur_buf) return HTTP_PARSE_ERROR;

    while (parser->cur_buf) {
        char *pos = parser->pos; // 현재 버퍼 위치
        char *last = parser->last; // 마지막 버퍼 위치
        sc_buf_t *cur_buf = parser->cur_buf; // 버퍼체인중 현재 처리할 버퍼

        switch (parser->state) {
            case HTTP_STATE_METHOD:
                parser->request->method.start = pos;  
                for (;;) {
                    while (pos < last && *pos != ' ') pos++;  // 현재 버퍼에서 공백 찾기

                    // 끝까지 온 경우 다음 버퍼 체인 탐색
                    if (pos == last) {
                        if (cur_buf->next) {  
                            cur_buf = cur_buf->next;
                            pos = cur_buf->start;
                            last = cur_buf->last;
                            continue;
                        }
                        return HTTP_PARSE_CONTINUE;  // 더 이상 데이터가 없으면 추가 데이터 기다림
                    }

                    parser->request->method.length = pos - parser->request->method.start;
                    parser->state = HTTP_STATE_PATH;
                    pos++;  // 공백 문자 넘김
                    break;
                }
                break;

            case HTTP_STATE_PATH:
                parser->request->path.start = pos;
                for(;;){
                    while (pos < last && *pos != ' ' && *pos != '?') pos++;

                    if (pos == last) {
                        if (cur_buf->next) {
                            cur_buf = cur_buf->next;
                            pos = cur_buf->start;
                            last = cur_buf->last;
                            continue;
                        }
                        return HTTP_PARSE_CONTINUE;
                    }

                    // 포트 번호가 포함된 경우 파싱
                    if (*pos == ':') {
                        pos++;
                        char *port_start = pos;

                        while (pos < last && *pos >= '0' && *pos <= '9') pos++;  // 숫자 찾기

                        if (pos == last) {
                            if (cur_buf->next) {
                                cur_buf = cur_buf->next;
                                pos = cur_buf->start;
                                last = cur_buf->last;
                                continue;
                            }
                            return HTTP_PARSE_CONTINUE;
                        }

                        // 포트 길이 계산 후 숫자로 변환
                        int port_length = pos - port_start;
                        if (port_length > 0) {
                            char port_buf[6] = {0};
                            memcpy(port_buf, port_start, port_length);
                            port_buf[port_length] = '\0';
                            parser->request->port = atoi(port_buf);
                        }
                    } else {
                        parser->request->port = -1;  // 포트 명시 안 되어 있으면 -1
                    }

                    parser->request->path.length = pos - parser->request->path.start;
                    if (*pos == '?') {
                        pos++;
                        parser->state = HTTP_STATE_QUERY;
                    } else {
                        parser->state = HTTP_STATE_VERSION;
                        pos++;
                    }
                    break;
                }
                break;

            case HTTP_STATE_QUERY:
                parser->request->query.start = pos;
                for (;;) {
                    while (pos < last && *pos != ' ') pos++;

                    if (pos == last) {
                        if (cur_buf->next) {
                            cur_buf = cur_buf->next;
                            pos = cur_buf->start;
                            last = cur_buf->last;
                            continue;
                        }
                        return HTTP_PARSE_CONTINUE;
                    }

                    parser->request->query.length = pos - parser->request->query.start;
                    parser->state = HTTP_STATE_VERSION;
                    pos++;
                    break;
                }
                break;

            case HTTP_STATE_VERSION:
                for (;;) {
                    if (last - pos < 8) {
                        if (cur_buf->next) {
                            cur_buf = cur_buf->next;
                            pos = cur_buf->start;
                            last = cur_buf->last;
                            continue;
                        }
                        return HTTP_PARSE_CONTINUE;
                    }

                    if (strncmp(pos, "HTTP/1.", 7) != 0) return HTTP_PARSE_ERROR;
                    parser->request->protocol_minor_version = pos[7] - '0';
                    parser->state = HTTP_STATE_HEADER;
                    pos += 8;
                    break;
                }
                break;

            case HTTP_STATE_HEADER:
                while (cur_buf) {
                    if (pos == last) {
                        cur_buf = cur_buf->next;
                        if (cur_buf) { pos = cur_buf->start; last = cur_buf->last; }
                        else return HTTP_PARSE_CONTINUE;
                    }
                    // 헤더 끝 감지(\r\n\r\n)
                    if (*pos == '\r' && (pos + 1 < last) && *(pos + 1) == '\n') {
                        pos += 2; // 첫 번째 CRLF 넘김
            
                        // 다음 문자가 또 CRLF라면 헤더가 끝났음 -> 본문으로 이동
                        if (*pos == '\r' && (pos + 1 < last) && *(pos + 1) == '\n') {
                            parser->state = HTTP_STATE_BODY;
                            pos += 2; // 최종적으로 \r\n\r\n 넘김
                            break;
                        }
                    }

                    HTTPHeaderField *field = (HTTPHeaderField *)malloc(sizeof(HTTPHeaderField));
                    if (!field) return HTTP_PARSE_ERROR;

                    // HTTPHeaderField 리스트는 마지막에 파싱된 헤더가 head 노드가 됨
                    field->next = parser->request->header;
                    parser->request->header = field;

                    // 헤더 이름 파싱
                    field->name.start = pos;
                    while (pos < last && *pos != ':') pos++;
                    if (pos == last) break;
                    field->name.length = pos - field->name.start;
                    pos++;

                    // 헤더의 값 앞 공백 제거
                    while (pos < last && (*pos == ' ' || *pos == '\t')) pos++;

                    // 헤더 값 파싱
                    field->value.start = pos;
                    while (pos < last && *pos != '\r') pos++;
                    if (pos == last) break;
                    field->value.length = pos - field->value.start;

                }
                break;

            case HTTP_STATE_BODY:
                parser->request->body.start = pos;
                parser->request->body.length = 0;
                for (;;) {
                    parser->request->body.length += last - pos; // 버퍼 체인을 서치하며 body length 값 업데이트
                    if (!cur_buf->next) break;
                    cur_buf = cur_buf->next;
                    pos = cur_buf->start;
                    last = cur_buf->last;
                }
                
                // 파싱 완료
                parser->state = HTTP_STATE_DONE;

                // host 문자열 변환
                HTTPHeaderField *host_header = find_header(parser->request, "Host");
                if(host_header != NULL) {
                    char* colon_pos = memchr(host_header->value.start, ':', host_header->value.length);
                    if(colon_pos) {
                        host_header->value.length = colon_pos - host_header->value.start;
                    }
                    parser->request->s_host = HTTPString_to_value(host_header->value);
                }

                return HTTP_PARSE_OK;

            case HTTP_STATE_DONE:
                return HTTP_PARSE_OK;

            case HTTP_STATE_ERROR:
                return HTTP_PARSE_ERROR;
        }

        parser->pos = pos;
        parser->cur_buf = cur_buf;
    }

    return HTTP_PARSE_CONTINUE;
}

// 특정 헤더 탐색
HTTPHeaderField *find_header(HTTPRequest *request, const char *header_name) {
    HTTPHeaderField *header = request->header;
    size_t name_len = strlen(header_name);

    while (header) {
        if (header->name.length == name_len && strncasecmp(header->name.start, header_name, name_len) == 0) {
            return header;  // 일치하는 헤더를 찾으면 반환
        }
        header = header->next;
    }
    return NULL;  // 해당 헤더를 찾지 못하면 NULL 반환
}

// 호출자쪽에서 free 필요
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
    if (request == NULL) return;

    if (request->header != NULL) {
        HTTPHeaderField *header = request->header;

        while (header) {
            HTTPHeaderField *next = header->next;
            free(header);
            header = next;
        }
    }
    
    if (request->s_host != NULL) {
        free(request->s_host);
    }

    free(request);
}
