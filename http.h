#ifndef HTTP
#define HTTP

#include "sc_mem_pool.h"

#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define MAX_LINE_SIZE 4096
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 2048
#define MAX_PROTOCOL_SIZE 16
#define MAX_HEADER_SIZE 8192

#define str3_cmp(m, c0, c1, c2) m[0] == c0 && m[1] == c1 && m[2] == c2
#define str4_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3
#define str7_cmp(m, c0, c1, c2, c3 ,c4, c5, c6) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4 && m[5] == c5 && m[6] == c6
#define str6_cmp(m, c0, c1, c2, c3 ,c4, c5) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4 && m[5] == c5
#define str5_cmp(m, c0, c1, c2, c3 ,c4) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4

//////////////////////////////////////
typedef enum Req_Method_State {
    STATE_GET,
    STATE_POST,
    STATE_PUT,
    STATE_HEAD,
    STATE_CONNECT,
    STATE_OPTIONS,
    STATE_DELETE,
    STATE_TRACE,
    DEFAULT
} Req_Method_State;

typedef enum {
    HTTP_STATE_INIT,
    HTTP_STATE_METHOD,
    HTTP_STATE_PATH,
    HTTP_STATE_QUERY,
    HTTP_STATE_VERSION,
    HTTP_STATE_HEADER,
    HTTP_STATE_BODY,
    HTTP_STATE_DONE,
    HTTP_STATE_ERROR
} HTTPParseState;

typedef enum {
    HTTP_PARSE_CONTINUE,
    HTTP_PARSE_OK,
    HTTP_PARSE_ERROR
} HTTPParseResult;

typedef struct HTTPString {
    char *start;
    size_t length;
} HTTPString;

typedef struct HTTPHeaderField {
    HTTPString name;
    HTTPString value;
    struct HTTPHeaderField *next;
} HTTPHeaderField;

typedef struct HTTPQueryParam {
    HTTPString name;
    HTTPString value;
    struct HTTPQueryParam *next;
} HTTPQueryParam;

typedef struct HTTPRequest {
    int protocol_minor_version;
    HTTPString method;
    HTTPString path;
    HTTPString query;
    int port;
    HTTPString host;
    // HTTPQueryParam *query;
    HTTPHeaderField *header;
    HTTPString body;
    long length;
    char* s_host;
} HTTPRequest;

typedef struct {
    HTTPRequest *request;
    sc_buf_t *cur_buf;
    char *pos;
    char *last;
    HTTPParseState state;
} HTTPRequestParser;

char *trim_whitespace(char *str);

HTTPRequestParser *create_parser(sc_buf_t *buf);
void free_parser(HTTPRequestParser *parser);
HTTPParseResult parse_http_request(HTTPRequestParser *parser);

HTTPHeaderField *find_header(HTTPRequest *request, const char *header_name);
char *HTTPString_to_value(HTTPString str);
void free_request(HTTPRequest *request);

int get_IP(char* ip_str, const char* hostname, int port);

#endif //HTTP