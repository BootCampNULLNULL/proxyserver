#include "client_handler.h"
#include "server_forwarder.h"
#include "logger.h"
#include "security_checker.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 4096

/**
 * @brief HTTPS 클라이언트 요청을 처리하는 함수
 *
 * 클라이언트의 요청을 읽고 보안 정책 위반 여부를 검사합니다.
 * 요청을 서버로 전달하고 응답을 반환한 후, 로그를 기록합니다.
 *
 * @param client_fd 클라이언트 소켓 파일 디스크립터
 * @param ssl_ctx SSL 통신을 위한 SSL 컨텍스트
 */
void handle_client(int client_fd, SSL_CTX* ssl_ctx) {
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_fd);

    // SSL 연결 수락
if (SSL_accept(ssl) <= 0) {
    cerr << "[ERROR] SSL 연결 실패" << endl;
    ERR_print_errors_fp(stderr);  // 오류 세부사항 출력
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        cerr << "[DEBUG] 클라이언트 인증 실패" << endl;
    }
    close(client_fd);
    return;
} else {
    cerr << "[DEBUG] SSL 핸드쉐이크 성공" << endl;  // 핸드쉐이크 성공
}


    char buffer[BUFFER_SIZE];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        cerr << "[ERROR] SSL_read 실패" << endl;
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    buffer[bytes] = '\0';
    string request(buffer);

    cerr << "[DEBUG] 클라이언트 요청:\n" << request << endl;

    // 보안 정책 위반 검사
    if (is_policy_violation(request)) {
        string forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\n";
        SSL_write(ssl, forbidden_response.c_str(), forbidden_response.length());
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    // 요청을 서버로 전달 (HTTPS)
    string response = forward_request_to_server(request, true);

    if (response.empty()) {
        cerr << "[ERROR] 서버 응답 없음" << endl;
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    // 클라이언트로 응답 전송
    if (SSL_write(ssl, response.c_str(), response.length()) <= 0) {
        cerr << "[ERROR] SSL_write 실패" << endl;
    } else {
        cerr << "[DEBUG] 응답 전송 완료" << endl;
    }

    // 로그 기록
    log_request(client_fd, request);

    SSL_free(ssl);
    close(client_fd);
}

/**
 * @brief HTTP 클라이언트 요청을 처리하는 함수
 *
 * 클라이언트로부터 HTTP 요청을 읽고, 보안 정책을 검사하며, 요청을 서버로 전달한 후 응답을 반환합니다.
 *
 * @param client_fd 클라이언트 소켓 파일 디스크립터
 */
void handle_http_request(int client_fd) {
    char buffer[BUFFER_SIZE];
    int bytes = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes <= 0) {
        cerr << "[ERROR] HTTP 요청 읽기 실패 또는 클라이언트 연결 종료" << endl;
        close(client_fd);
        return;
    }

    buffer[bytes] = '\0';
    cerr << "[DEBUG] HTTP 요청:\n" << buffer << endl;

    // 보안 정책 위반 검사
    if (is_policy_violation(buffer)) {
        string forbidden_response = "HTTP/1.1 403 Forbidden\r\n\r\n";
        write(client_fd, forbidden_response.c_str(), forbidden_response.length());
        close(client_fd);
        return;
    }

    // 요청을 서버로 전달 (HTTP)
    string response = forward_request_to_server(buffer, false);
    if (response.empty()) {
        cerr << "[ERROR] 대상 서버 응답 없음" << endl;
        close(client_fd);
        return;
    }

    // 응답 전송
    ssize_t sent_bytes = write(client_fd, response.c_str(), response.size());
    if (sent_bytes <= 0) {
        cerr << "[ERROR] HTTP 응답 전송 실패" << endl;
    } else {
        cerr << "[DEBUG] HTTP 응답 전송 완료: " << sent_bytes << " 바이트" << endl;
    }

    // 로그 기록
    log_request(client_fd, buffer);

    close(client_fd);
}

