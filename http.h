#ifndef HTTP
#define HTTP
#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define MAX_LINE_SIZE 4096
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 2048
#define MAX_PROTOCOL_SIZE 16
#define MAX_HEADER_SIZE 8192

#define str3_cmp(m, c0, c1, c2) m[0] == c0 && m[1] == c1 && m[2] == c2
#define str4_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3
#define str7_cmp(m, c0, c1, c2, c3) m[0] == c0 && m[1] == c1 && m[2] == c2 && m[3] == c3 && m[4] == c4 && m[5] == c5 && m[6] == c6

//////////////////////////////////////
typedef struct HTTPHeaderField {
    char *name;
    char *value;
    struct HTTPHeaderField *next;
} HTTPHeaderField;

// HTTP 쿼리 파라미터를 나타내는 구조체
typedef struct HTTPQueryParam {
    char *name;
    char *value;
    struct HTTPQueryParam *next;
} HTTPQueryParam;

// HTTP 요청 데이터를 나타내는 구조체
typedef struct HTTPRequest {
    int protocol_minor_version;
    char *method;
    char *path;
    int port;
    char* host;
    struct HTTPQueryParam *query;
    struct HTTPHeaderField *header;
    char *body;
    long length;
} HTTPRequest;
/////////////////////////////////////

char *trim_whitespace(char *str);
void parse_query_params(char *query_string, HTTPRequest *request);
void read_request_line(const char *buffer, HTTPRequest *request);
void read_header_field(const char *buffer, HTTPRequest *request);
HTTPRequest *read_request(const char *buffer);
char* find_Host_field(HTTPHeaderField* head);
int find_port(char* host);
void free_request(HTTPRequest *request);
int get_IP(char* ip_str, const char* hostname, int port);

#endif //HTTP