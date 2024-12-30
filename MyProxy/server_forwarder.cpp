#include "server_forwarder.h"
#include "ssl_initializer.h" // SSL 컨텍스트 초기화 함수 포함
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>  // getaddrinfo 사용
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sstream>
#include <iostream>

using namespace std;

#define BUFFER_SIZE 4096

/**
 * @brief 도메인 이름을 IP 주소로 변환하는 함수
 */
string resolve_hostname_to_ip(const string& hostname) {
    cerr << "[DEBUG] DNS 해석 중: " << hostname << endl;

    struct addrinfo hints{}, *res;
    hints.ai_family = AF_INET;  // IPv4 주소를 요청
    hints.ai_socktype = SOCK_STREAM;  // TCP 사용

    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) != 0) {
        perror("[ERROR] DNS 해석 실패");
        return "";
    }

    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, INET_ADDRSTRLEN);

    freeaddrinfo(res);  // 메모리 해제
    return string(ip_str);
}

/**
 * @brief SSL 컨텍스트 초기화
 */

/**
 * @brief 클라이언트 요청을 서버로 전달하고 응답을 반환하는 함수
 */
string forward_request_to_server(const string& request, bool use_ssl) {
    cerr << "=== 서버 전달 시작 ===" << endl;

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    if (use_ssl) {
        const string ca_cert = "/home/abc/MyProxy/ssl/ca-cert.pem";
        const string cert_file = "/home/abc/MyProxy/ssl/proxy-cert.pem";
        const string key_file = "/home/abc/MyProxy/ssl/proxy-key.pem";
        ctx = initialize_ssl_context(ca_cert, cert_file, key_file);
    }

    // 대상 서버와 통신할 소켓 생성
    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd == -1) {
        perror("서버 소켓 생성 실패");
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }
    cerr << "[DEBUG] 서버 소켓 생성 성공 (FD: " << server_fd << ")" << endl;

    // 대상 서버 주소 설정
    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(use_ssl ? 443 : 80);  // HTTPS(443) 또는 HTTP(80) 포트

    // HTTP 요청에서 호스트 추출
    string host = extract_host_from_request(request);
    if (host.empty()) {
        cerr << "[ERROR] Host 헤더 추출 실패" << endl;
        close(server_fd);
        if (ctx) SSL_CTX_free(ctx);
        return "HTTP/1.1 400 Bad Request\r\n\r\n";
    }
    cerr << "[DEBUG] 추출된 호스트: " << host << endl;

    // DNS 해석으로 IP 주소 변환
    string ip_address = resolve_hostname_to_ip(host);
    if (ip_address.empty()) {
        cerr << "[ERROR] 대상 서버 IP 해석 실패" << endl;
        close(server_fd);
        if (ctx) SSL_CTX_free(ctx);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }
    cerr << "[DEBUG] 대상 서버 IP: " << ip_address << endl;

    if (inet_pton(AF_INET, ip_address.c_str(), &server_addr.sin_addr) <= 0) {
        perror("[ERROR] IP 주소 변환 실패");
        close(server_fd);
        if (ctx) SSL_CTX_free(ctx);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }
    cerr << "[DEBUG] 대상 서버 주소 설정 완료" << endl;

    // 서버 연결
    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("[ERROR] 대상 서버 연결 실패");
        close(server_fd);
        if (ctx) SSL_CTX_free(ctx);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }
    cerr << "[DEBUG] 대상 서버 연결 성공: " << host << endl;

    if (use_ssl) {
        // SSL 연결 설정
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, server_fd);
        if (SSL_connect(ssl) <= 0) {
            cerr << "[ERROR] SSL 연결 실패" << endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(server_fd);
            SSL_CTX_free(ctx);
            return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        }
        cerr << "[DEBUG] SSL 연결 성공" << endl;
    }

    // 요청 데이터 전송
    cerr << "[DEBUG] 요청 데이터 전송 중 (크기: " << request.length() << " 바이트)" << endl;
    if (use_ssl) {
        if (SSL_write(ssl, request.c_str(), request.length()) <= 0) {
            cerr << "[ERROR] SSL 요청 데이터 전송 실패" << endl;
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(server_fd);
            SSL_CTX_free(ctx);
            return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        }
    } else {
        if (send(server_fd, request.c_str(), request.length(), 0) == -1) {
            perror("[ERROR] 요청 데이터 전송 실패");
            close(server_fd);
            return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
        }
    }
    cerr << "[DEBUG] 요청 데이터 전송 완료" << endl;

    // 응답 데이터 수신
    cerr << "[DEBUG] 대상 서버 응답 수신 중..." << endl;
    char buffer[BUFFER_SIZE];
    stringstream response;
    int bytes;
    while (true) {
        if (use_ssl) {
            bytes = SSL_read(ssl, buffer, sizeof(buffer));
        } else {
            bytes = recv(server_fd, buffer, sizeof(buffer), 0);
        }
        if (bytes <= 0) break;
        response.write(buffer, bytes);
        cerr << "[DEBUG] 수신된 데이터 크기: " << bytes << " 바이트" << endl;
    }

    if (bytes < 0) {
        cerr << "[ERROR] 응답 데이터 수신 실패" << endl;
        ERR_print_errors_fp(stderr);
    } else {
        cerr << "[DEBUG] 대상 서버 응답 종료" << endl;
    }

    // SSL 및 소켓 종료
    if (use_ssl) SSL_free(ssl);
    close(server_fd);
    if (ctx) SSL_CTX_free(ctx);

    cerr << "=== 서버 전달 종료 ===" << endl;
    return response.str();
}

/**
 * @brief HTTP 요청에서 Host 헤더를 추출하는 함수
 */
string extract_host_from_request(const string& request) {
    cerr << "[DEBUG] Host 헤더 추출 중..." << endl;
    string host_header = "Host: ";
    auto start = request.find(host_header);
    if (start == string::npos) {
        cerr << "[ERROR] Host 헤더가 요청에 포함되지 않음" << endl;
        return "";
    }

    start += host_header.length();
    auto end = request.find("\r\n", start);
    if (end == string::npos) {
        cerr << "[ERROR] Host 헤더 끝을 찾을 수 없음" << endl;
        return "";
    }

    string host = request.substr(start, end - start);
    cerr << "[DEBUG] 추출된 호스트: " << host << endl;
    return host;
}

