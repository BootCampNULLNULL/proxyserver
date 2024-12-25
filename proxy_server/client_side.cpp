#include "client_side.h"
#include "check_policy.h"
#include "server_side.h"
#include "access_log.h"
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void handle_client(int client_fd, SSL_CTX* ctx) {
    SSL* client_ssl = SSL_new(ctx);
    SSL_set_fd(client_ssl, client_fd);

    if (SSL_accept(client_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(client_fd);
        return;
    }

    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(client_ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        SSL_free(client_ssl);
        close(client_fd);
        return;
    }

    buffer[bytes] = '\0';
    std::string request(buffer);

    // 정책 검사
    if (!check_policy(request)) {
        SSL_write(client_ssl, "HTTP/1.1 403 Forbidden\r\n\r\n", 26);
        SSL_free(client_ssl);
        close(client_fd);
        return;
    }

    // 서버와 통신
    std::string response = forward_to_server(request);

    // 응답 보내기
    SSL_write(client_ssl, response.c_str(), response.length());

    // 로그 기록
    log_access(client_fd, request);

    SSL_free(client_ssl);
    close(client_fd);
}
