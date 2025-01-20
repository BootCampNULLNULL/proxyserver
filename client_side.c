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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
// #include "http.h"
// #include "ssl_conn.h"
// #include "client_side.h"


#define SERVERPORT 5051
#define MAX_EVENTS 1000
#define DEFUALT_HTTPS_PORT 443
#define DEFUALT_HTTP_PORT 80
#define CERT_FILE "/home/ubuntu/securezone/certificate.pem" // 인증서 파일 경로
#define KEY_FILE  "/home/ubuntu/securezone/private_key.pem"  // 키 파일 경로
#define MAX_BUFFER_SIZE 4096

#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define MAX_LINE_SIZE 4096
#define MAX_METHOD_SIZE 16
#define MAX_URI_SIZE 2048
#define MAX_PROTOCOL_SIZE 16
#define MAX_HEADER_SIZE 8192


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

typedef enum task_state_t {
    STATE_CLIENT_READ,
    STATE_REMOTE_CONNECT,
    STATE_CLIENT_SSL_ACCEPT,
    STATE_CLIENT_SSL_READ,
    STATE_REMOTE_SSL_CONNECT,
    STATE_REMOTE_WRITE,
    STATE_REMOTE_READ,
    STATE_CLIENT_WRITE
} task_state_t;

typedef struct task_t {
    int client_fd;
    bool client_side_https;
    SSL_CTX* client_ctx;
    SSL* client_ssl;
    int remote_fd;
    SSL_CTX* remote_ctx;
    SSL* remote_ssl;
    bool remote_side_https;
    char buffer[MAX_BUFFER_SIZE];
    int buffer_len;
    HTTPRequest* req;
    task_state_t state;
} task_t;


static void set_nonblocking(int fd);
static void log_exit(const char *fmt, ...);
static void* xmalloc(size_t sz);
static int get_IP(char* ip_str, const char* hostname, int port);
static int connect_remote_http(const char* host, int port);
SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx);
char* find_Host_field(HTTPHeaderField* head);
int find_port(char* host);

// Non-blocking 설정 함수
void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void log_exit(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
    
    va_end(ap);
    exit(1);
}

void* xmalloc(size_t sz)
{
    void *p;

    p = malloc(sz);
    if (!p) log_exit("failed to allocate memory");
    return p;
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


int connect_remote_http(const char* hostname, int port) {

    struct hostent *host;
    if((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    // remote 소켓 연결
    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(remote_fd < 0) {
        log_exit("Remote socket creation failed");
        //perror("Remote socket creation failed");
    }
    set_nonblocking(remote_fd);

    struct sockaddr_in remoteaddr;
    memset(&remoteaddr, 0, sizeof(remoteaddr));
    remoteaddr.sin_family = AF_INET;
    remoteaddr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);
    remoteaddr.sin_port = htons(port);

    connect(remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));

    return remote_fd;
}


SSL* connect_remote_https(int remote_fd, SSL_CTX* remote_ctx) {
    // SSL 연결
    remote_ctx = SSL_CTX_new(TLS_client_method());
    if (!remote_ctx) {
        perror("Failed to create SSL context for remote server");
        close(remote_fd);
        return NULL;
    }
    SSL *remote_ssl = SSL_new(remote_ctx);
    SSL_set_fd(remote_ssl, remote_fd);

    // if (SSL_connect(remote_ssl) <= 0) {
    //     fprintf(stderr, "SSL handshake with remote server failed\n");
    //     ERR_print_errors_fp(stderr);
    //     SSL_free(remote_ssl);
    //     SSL_CTX_free(remote_ctx);
    //     close(remote_fd);
    //     return NULL;
    // }

    return remote_ssl;
}

//////////////////////////////////////////////////////////////////////////////
// 문자열의 공백을 제거하는 유틸리티 함수
static char *trim_whitespace(char *str) {
    char *end;

    while (*str == ' ' || *str == '\t') str++;
    if (*str == 0) return str;

    end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\r')) end--;

    *(end + 1) = '\0';
    return str;
}

// 쿼리 파라미터를 파싱하는 함수
static void parse_query_params(char *query_string, HTTPRequest *request) {
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
static void read_request_line(const char *buffer, HTTPRequest *request) {
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
static void read_header_field(const char *buffer, HTTPRequest *request) {
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
///////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////
// OpenSSL 초기화
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// OpenSSL 정리
void cleanup_openssl() {
    EVP_cleanup();
}

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// 키 및 인증서 로드
EVP_PKEY *load_private_key(const char *key_file) {
    FILE *fp = fopen(key_file, "r");
    if (!fp) {
        perror("Unable to open CA key file");
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

X509 *load_certificate(const char *cert_file) {
    FILE *fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Unable to open CA cert file");
        return NULL;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

// RSA 키 생성
EVP_PKEY *generate_rsa_key() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to allocate EVP_PKEY\n");
        handle_openssl_error();
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Failed to create RSA object\n");
        EVP_PKEY_free(pkey);
        handle_openssl_error();
    }

    BIGNUM *bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Failed to set RSA_F4 exponent\n");
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        fprintf(stderr, "Failed to assign RSA to EVP_PKEY\n");
        RSA_free(rsa); // This frees `rsa` since EVP_PKEY_assign_RSA failed
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    BN_free(bn);
    return pkey;
}

// 특정 도메인에 대한 인증서 생성성
X509* generate_cert(const char* domain, EVP_PKEY* key, X509* ca_cert, EVP_PKEY* ca_key) {
    // 새로운 X.509 인증서 구조체 할당
    X509* cert = X509_new();
    if (!cert) handle_openssl_error();

    // 인증서 버전 설정
    X509_set_version(cert, 2);
    // 인증서 고유 일련 번호 설정
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // 인증서 유효기간 설정
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    // 인증서 주체이름 설정
    X509_NAME* name = X509_get_subject_name(cert);
    // 주체 이름에 도메인 정보 추가
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)domain, -1, -1, 0);
    // 인증서에 적용
    X509_set_subject_name(cert, name);

    // 
    X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, domain);
    if (san) {
        X509_add_ext(cert, san, -1);
        X509_EXTENSION_free(san);
    }

    // 인증서 발급자(issuer) 이름 설정 --> 루트 CA 인증서 사용
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    
    // 인증서에 사용할 공개 키 설정
    X509_set_pubkey(cert, key);

    // 루트CA 개인키로 암호화하여 디지털 서명 생성
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        handle_openssl_error();
    }
    
    // 
    return cert;
}


// 인증서 및 키 저장 함수
int save_cert_and_key(X509 *cert, EVP_PKEY *key, const char *cert_path, const char *key_path) {
    FILE *cert_file = fopen(cert_path, "wb");
    if (!cert_file) {
        perror("Failed to open certificate file");
        return 0;
    }

    if (!PEM_write_X509(cert_file, cert)) {
        perror("Failed to write certificate to file");
        fclose(cert_file);
        return 0;
    }
    fclose(cert_file);

    FILE *key_file = fopen(key_path, "wb");
    if (!key_file) {
        perror("Failed to open private key file");
        return 0;
    }

    if (!PEM_write_PrivateKey(key_file, key, NULL, NULL, 0, NULL, NULL)) {
        perror("Failed to write private key to file");
        fclose(key_file);
        return 0;
    }
    fclose(key_file);

    return 1;
}

SSL* handle_client_SSL_conn(int client_sock, 
char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX* client_ctx) {
    //
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_sock, response, strlen(response), 0);

    // 동적 키 생성 및 인증서 생성
    EVP_PKEY *key = generate_rsa_key();
    if (!key) {
        perror("Failed to generate RSA key");
        close(client_sock);
        return NULL;
    }

    X509 *dynamic_cert = generate_cert(domain, key, ca_cert, ca_key);
    if (!dynamic_cert) {
        EVP_PKEY_free(key);
        perror("Failed to generate dynamic certificate");
        close(client_sock);
        return NULL;
    }
    
    const char *cert_file = "/home/ubuntu/securezone/dynamic_cert.pem";
    const char *key_file = "/home/ubuntu/securezone/dynamic_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    // SSL 컨텍스트 생성
    client_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(client_ctx, "HIGH:!aNULL:!MD5:!RC4");

    if (!SSL_CTX_use_certificate_file(client_ctx, cert_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(client_ctx, key_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    SSL *ssl = SSL_new(client_ctx);
    SSL_set_fd(ssl, client_sock);

    // if (SSL_accept(ssl) <= 0) {
    //     fprintf(stderr, "SSL handshake failed\n");
    //     int err = SSL_get_error(ssl, -1);

    //     switch (err) {
    //         case SSL_ERROR_NONE:
    //             printf("No error occurred.\n");
    //             break;
    //         case SSL_ERROR_ZERO_RETURN:
    //             printf("Client closed the connection.\n");
    //             break;
    //         case SSL_ERROR_WANT_READ:
    //             printf("SSL_accept needs more data (WANT_READ).\n");
    //             break;
    //         case SSL_ERROR_WANT_WRITE:
    //             printf("SSL_accept needs to write more data (WANT_WRITE).\n");
    //             break;
    //         case SSL_ERROR_SYSCALL:
    //             perror("System call error during SSL_accept");
    //             break;
    //         case SSL_ERROR_SSL:
    //             printf("OpenSSL internal error occurred.\n");
    //             ERR_print_errors_fp(stderr);
    //             break;
    //         default:
    //             printf("Unknown error occurred: %d\n", err);
    //             break;
    //     }
    //     SSL_free(ssl);
    //     SSL_CTX_free(dynamic_ctx);
    //     EVP_PKEY_free(key);
    //     X509_free(dynamic_cert);
    //     close(client_sock);
    //     return NULL;
    // }
    
    X509_free(dynamic_cert);
    EVP_PKEY_free(key);

    return ssl;
    // SSL_free(ssl);
    // SSL_CTX_free(dynamic_ctx);
    // EVP_PKEY_free(key);
    // X509_free(dynamic_cert);
    // close(client_sock);
    
}
///////////////////////////////////////////////

int main(void) {
    const char *cert_file = CERT_FILE;
    const char *key_file = KEY_FILE;

    initialize_openssl();

    EVP_PKEY *ca_key = load_private_key(key_file);
    X509 *ca_cert = load_certificate(cert_file);
    if (!ca_key || !ca_cert) {
        fprintf(stderr, "Failed to load CA key or certificate\n");
        exit(EXIT_FAILURE);
    }

    int server_fd;
    struct sockaddr_in seraddr;

    // 서버 소켓 생성 및 설정
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    set_nonblocking(server_fd);

    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    seraddr.sin_port = htons(SERVERPORT);

    if (bind(server_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    listen(server_fd, 10);

    // epoll 인스턴스 생성
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("Epoll creation failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // 서버 소켓을 epoll에 등록
    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("Epoll control failed");
        close(server_fd);
        close(epoll_fd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (event_count == -1) {
            if (errno == EINTR) continue; // 신호로 인한 중단은 무시
            perror("Epoll wait failed");
            break;
        }

        for (int i = 0; i < event_count; i++) {
            if (events[i].data.fd == server_fd) {
                // 새 클라이언트 연결 처리
                while(1) {
                    struct sockaddr_in cliaddr;
                    socklen_t len = sizeof(cliaddr);
                    int client_fd = accept(server_fd, (struct sockaddr*)&cliaddr, &len);
                    if(client_fd < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK) {
                            // 모든 연결이 처리됨
                            break;
                        } else {
                            perror("Accept failed");
                            break;
                        }
                    }
                    set_nonblocking(client_fd);

                    task_t* task = (task_t*)malloc(sizeof(task_t));
                    
                    task->client_fd = client_fd;
                    task->client_side_https = false;
                    task->client_ssl = NULL;
                    task->client_ctx = NULL;
                    task->remote_fd = -1;
                    task->remote_ctx = NULL;
                    task->remote_ssl = NULL;
                    task->remote_side_https = false;
                    task->buffer_len = 0;
                    task->state = STATE_CLIENT_READ;

                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = task;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                }
            } else {
                task_t* task = (task_t*)events[i].data.ptr;

                if (!task) continue; // 안전 검사

                if (task->state == STATE_CLIENT_READ) {
                    // 클라이언트 데이터 수신
                    memset(task->buffer, 0, MAX_BUFFER_SIZE);
                    
                    // client 요청 recv
                    while (1) {
                        task->buffer_len = recv(task->client_fd, task->buffer, MAX_BUFFER_SIZE, 0);
                        if (task->buffer_len > 0) {
                            // 데이터 처리
                            printf("Data received from client: %d bytes\n", task->buffer_len);
                            printf("%.*s\n", task->buffer_len, task->buffer); // 안전하게 출력
                        } else if (task->buffer_len == 0) {
                            // 클라이언트 연결 종료
                            printf("Client disconnected\n");
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                            close(task->client_fd);
                            close(task->remote_fd);
                            free(task);
                            break; // 종료
                        } else { // task->buffer_len < 0
                            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                // 읽을 데이터가 더 이상 없음
                                break; // 이벤트 루프로 돌아감
                            } else {
                                // recv 실패
                                perror("recv failed");
                                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                                close(task->client_fd);
                                free(task);
                                exit(1);
                            }
                        }
                    }
                    // http 요청 로깅

                    // http 요청 파싱
                    task->req = read_request(task->buffer);
                    
                    // url db 조회 -> 필터링 
                    // CONNECT => ssl connect => GET or POST 요청 recv
                    if(strcmp(task->req->method, "CONNECT") == 0) {
                        task->client_side_https = true;
                        task->remote_side_https = true;
                        // if(task->req->port == -1) {
                        //     task->req->port = DEFUALT_HTTPS_PORT;
                        // }
                        printf("Host: %s\n", task->req->host); // 호스트 이름 출력
                        printf("Port: %d\n", task->req->port); // 포트 출력
                        printf("CONNECT request for %s:%d\n", task->req->host, task->req->port);
                        
                        // client ssl 연결
                        task->client_ssl = handle_client_SSL_conn(task->client_fd, task->req->host, task->req->port, ca_key, ca_cert, task->client_ctx);
                        task->state = STATE_CLIENT_SSL_ACCEPT;
                        continue;
                    } else {
                        if(task->req->port == -1) {
                            task->req->port = DEFUALT_HTTP_PORT;
                        }
                        // remote 연결
                        task->remote_fd = connect_remote_http(task->req->host, task->req->port);
                        printf("remote connection success\n");
                    }

                    ev.events = EPOLLOUT | EPOLLET;
                    ev.data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유 
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, &ev);

                    task->state = STATE_REMOTE_WRITE;
                    // free(req);  
                    
                } else if (task->state == STATE_CLIENT_SSL_ACCEPT) {
                    int ret = SSL_accept(task->client_ssl);
                    if (ret == 1) {
                        printf("Client SSL Handshake Success\n");

                        memset(task->buffer, 0, MAX_BUFFER_SIZE);
                        task->buffer_len = SSL_read(task->client_ssl, task->buffer, MAX_BUFFER_SIZE);

                        // 다음 이벤트 발생 이전에 요청이 들어왔으면
                        if (task->buffer_len > 0) {
                            printf("%s\n", task->buffer);
                            free_request(task->req);
                            task->req = read_request(task->buffer);

                            if(task->req->port == -1) {
                                task->req->port = DEFUALT_HTTPS_PORT;
                            }
                            // remote ssl 연결
                            task->remote_fd = connect_remote_http(task->req->host, task->req->port);
                            task->remote_ssl = connect_remote_https(task->remote_fd, task->remote_ctx);
                            
                            ev.events = EPOLLIN | EPOLLET;
                            ev.data.ptr = task;
                            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, &ev);
                            int ret = SSL_connect(task->remote_ssl);

                            int err = SSL_get_error(task->remote_ssl, ret);
                            switch(err) {
                                case SSL_ERROR_WANT_READ:
                                    task->state = STATE_REMOTE_SSL_CONNECT;
                                    continue;
                                case SSL_ERROR_WANT_WRITE:
                                    task->state = STATE_REMOTE_SSL_CONNECT;
                                    continue;
                                default:
                                    printf("Remote SSL Handshake error - %d\n", err);
                                    exit(1);
                            }

                            task->state = STATE_REMOTE_SSL_CONNECT;
                        } else {
                            // 다음 이벤트를 기다려야 하면
                            printf("wait event\n");
                            task->state = STATE_CLIENT_SSL_READ;
                            ev.events = EPOLLIN | EPOLLET;
                            ev.data.ptr = task;
                            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                        }
                        continue;
                    }

                    // SSL_accept가 완료되지 않은 경우
                    int err = SSL_get_error(task->client_ssl, ret);
                    switch(err) {
                        case SSL_ERROR_WANT_READ:
                            continue;
                        case SSL_ERROR_WANT_WRITE:
                            continue;
                        default:
                            printf("Client SSL Handshake error - %d\n", err);
                            exit(1);
                    }
                } else if (task->state == STATE_CLIENT_SSL_READ) {
                    
                    memset(task->buffer, 0, MAX_BUFFER_SIZE);
                    task->buffer_len = SSL_read(task->client_ssl, task->buffer, MAX_BUFFER_SIZE);

                    if (task->buffer_len <= 0) {
                        int err = SSL_get_error(task->client_ssl, task->buffer_len);
                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                            // SSL_read needs more data
                            continue;
                        } else {
                            printf("Client SSL Read error - %d\n", err);
                            exit(1);
                        }
                    }

                    free_request(task->req);
                    task->req = read_request(task->buffer);

                    if(task->req->port == -1) {
                        task->req->port = DEFUALT_HTTPS_PORT;
                    }
                    // remote ssl 연결
                    task->remote_fd = connect_remote_http(task->req->host, task->req->port);
                    task->remote_ssl = connect_remote_https(task->remote_fd, task->remote_ctx);
                    
                    ev.events = EPOLLIN | EPOLLET;
                    ev.data.ptr = task;
                    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, task->remote_fd, &ev);

                    task->state = STATE_REMOTE_SSL_CONNECT;

                } else if (task->state == STATE_REMOTE_SSL_CONNECT) {
                    int ret = SSL_connect(task->remote_ssl);
                    if (ret == 1) {
                        printf("Remote SSL Handshake Success\n");

                        ev.events = EPOLLOUT | EPOLLET;
                        ev.data.ptr = task;     // remote 소켓은 client 소켓의 task 구조체 공유
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, &ev);

                        task->state = STATE_REMOTE_WRITE;
                    } else {
                        int err = SSL_get_error(task->remote_ssl, ret);
                        switch(err) {
                            case SSL_ERROR_WANT_READ:
                                continue;
                            case SSL_ERROR_WANT_WRITE:
                                continue;
                            default:
                                printf("SSL Handshake error - %d\n", err);
                                exit(1);
                        }
                    }
                } else if (task->state == STATE_REMOTE_WRITE) {
                    // 원격 서버로 데이터 송신
                    if (task->remote_side_https == true) {
                        SSL_write(task->remote_ssl, task->buffer, MAX_BUFFER_SIZE);
                        task->state = STATE_REMOTE_READ;
                        ev.events = EPOLLIN | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, &ev);
                    } else {
                        send(task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
                        task->state = STATE_REMOTE_READ;
                        ev.events = EPOLLIN | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->remote_fd, &ev);
                    }

                } else if (task->state == STATE_REMOTE_READ) {
                    // 원격 서버 데이터 수신
                    // recv 값 유효성 검사해서 유효하지 못한 응답일 경우 소켓 닫는 로직 필요
                    if(task->remote_side_https == true) {
                        //SSL_read()
                        memset(task->buffer, 0, MAX_BUFFER_SIZE);
                        task->buffer_len = SSL_read(task->remote_ssl, task->buffer, MAX_BUFFER_SIZE);

                        printf("Data received from remote: %d bytes\n", task->buffer_len);
                        printf("%s\n", task->buffer);

                        task->state = STATE_CLIENT_WRITE;
                        ev.events = EPOLLOUT | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                    } else {
                        memset(task->buffer, 0, MAX_BUFFER_SIZE);
                        while (1) {
                            int ret = recv(task->remote_fd, task->buffer, MAX_BUFFER_SIZE, 0);
                            if (ret > 0) {
                                // 데이터 처리
                                printf("Data received from remote: %d bytes\n", ret);
                                printf("%s\n", task->buffer); // 안전하게 출력
                                ret = task->buffer_len;
                            } else if (ret == 0) {
                                // 클라이언트 연결 종료
                                printf("remote disconnected\n");
                                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                                // epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                                // close(task->client_fd);
                                // close(task->remote_fd);
                                // free(task);
                                break; // 종료
                            } else { // task->buffer_len < 0
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    // 읽을 데이터가 더 이상 없음
                                    break; // 이벤트 루프로 돌아감
                                } else {
                                    // recv 실패
                                    perror("recv failed");
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                                    close(task->client_fd);
                                    close(task->remote_fd);
                                    free(task);
                                    exit(1);
                                }
                            }
                        }

                        task->state = STATE_CLIENT_WRITE;
                        ev.events = EPOLLOUT | EPOLLET;
                        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                    }
                } else if (task->state == STATE_CLIENT_WRITE) {
                    if(task->client_side_https == true) {
                        // SSL_write()
                        SSL_write(task->client_ssl, task->buffer, task->buffer_len);
                        // task->state = STATE_CLIENT_READ;
                        // ev.events = EPOLLIN | EPOLLET;
                        // epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                        free_request(task->req);
                        SSL_free(task->client_ssl);
                        SSL_free(task->remote_ssl);
                        SSL_CTX_free(task->client_ctx);
                        SSL_CTX_free(task->remote_ctx);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                        close(task->remote_fd);
                        close(task->client_fd);
                        free(task);
                    } else {
                        send(task->client_fd, task->buffer, task->buffer_len, 0);
                        // 세션 유지시
                        // task->state = STATE_CLIENT_READ;
                        // ev.events = EPOLLIN | EPOLLET;
                        // epoll_ctl(epoll_fd, EPOLL_CTL_MOD, task->client_fd, &ev);
                        // free(task->req);

                        // 세션 종료시
                        free_request(task->req);
                        SSL_free(task->client_ssl);
                        SSL_free(task->remote_ssl);
                        SSL_CTX_free(task->client_ctx);
                        SSL_CTX_free(task->remote_ctx);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->client_fd, NULL);
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, task->remote_fd, NULL);
                        close(task->remote_fd);
                        close(task->client_fd);
                        free(task);
                    }
                }
            }
        }
    }
    close(server_fd);
    close(epoll_fd);
    
    return 0;
}

// 문제점 0. HTTPS 통신 테스트 필요
// 문제점 1. STATE_CLIENT_WRITE 상태에서 클라이언트로 최종 수신 종료 이후 세션 유지 or 종료
// 문제점 2. ssl 관련 메모리 free