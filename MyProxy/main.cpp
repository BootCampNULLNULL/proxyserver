#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <queue>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <cstring>
#include "client_handler.h"
#include "ssl_initializer.h"
#include "server_forwarder.h"

using namespace std;

#define MAX_EVENTS 1000
#define HTTP_PORT 8080
#define HTTPS_PORT 8443
#define BUFFER_SIZE 4096

// 클라이언트 큐와 동기화를 위한 mutex 및 조건 변수
mutex queue_mutex;
condition_variable queue_cv;
queue<pair<int, bool>> client_queue;

/**
 * @brief 클라이언트 요청을 처리하는 스레드 함수
 *
 * 큐에서 클라이언트를 가져와 요청을 처리합니다.
 *
 * @param ssl_ctx HTTPS 요청 처리를 위한 SSL 컨텍스트
 */
void process_client_requests(SSL_CTX* ssl_ctx) {
    while (true) {
        unique_lock<mutex> lock(queue_mutex);

        // 큐가 비어 있으면 대기
        queue_cv.wait(lock, [] { return !client_queue.empty(); });

        // 큐에서 클라이언트 FD와 요청 유형(HTTP/HTTPS)을 가져옴
        auto [client_fd, use_ssl] = client_queue.front();
        client_queue.pop();
        lock.unlock();

        // 요청 처리
        if (use_ssl) {
            handle_client(client_fd, ssl_ctx);  // HTTPS 처리
        } else {
            handle_http_request(client_fd);    // HTTP 처리
        }
    }
}

int main() {
    // 인증서 파일 경로
    const string ca_cert = "/home/abc/MyProxy/ssl/ca-cert.pem";
    const string cert_file = "/home/abc/MyProxy/ssl/proxy-cert.pem";
    const string key_file = "/home/abc/MyProxy/ssl/proxy-key.pem";

    // SSL 초기화 및 인증서 로드
    SSL_CTX* ssl_ctx = initialize_ssl_context(ca_cert, cert_file, key_file);
    if (!ssl_ctx) {
        cerr << "[ERROR] SSL 컨텍스트 초기화 실패" << endl;
        return EXIT_FAILURE;
    }
    cout << "[INFO] SSL 컨텍스트 초기화 성공" << endl;

    // HTTP 및 HTTPS 소켓 생성
    int http_socket = socket(AF_INET, SOCK_STREAM, 0);
    int https_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket == -1 || https_socket == -1) {
        perror("[ERROR] 소켓 생성 실패");
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // HTTP 소켓 설정
    struct sockaddr_in http_addr{};
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);

    if (bind(http_socket, (struct sockaddr*)&http_addr, sizeof(http_addr)) == -1) {
        perror("[ERROR] HTTP 소켓 바인딩 실패");
        close(http_socket);
        close(https_socket);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    if (listen(http_socket, SOMAXCONN) == -1) {
        perror("[ERROR] HTTP 소켓 리슨 실패");
        close(http_socket);
        close(https_socket);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // HTTPS 소켓 설정
    struct sockaddr_in https_addr{};
    https_addr.sin_family = AF_INET;
    https_addr.sin_addr.s_addr = INADDR_ANY;
    https_addr.sin_port = htons(HTTPS_PORT);

    if (bind(https_socket, (struct sockaddr*)&https_addr, sizeof(https_addr)) == -1) {
        perror("[ERROR] HTTPS 소켓 바인딩 실패");
        close(http_socket);
        close(https_socket);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    if (listen(https_socket, SOMAXCONN) == -1) {
        perror("[ERROR] HTTPS 소켓 리슨 실패");
        close(http_socket);
        close(https_socket);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    cout << "[INFO] HTTP 프록시 서버가 포트 " << HTTP_PORT << "에서 실행 중입니다." << endl;
    cout << "[INFO] HTTPS 프록시 서버가 포트 " << HTTPS_PORT << "에서 실행 중입니다." << endl;

    // 클라이언트 요청을 처리할 워커 스레드 생성
    vector<thread> workers;
    for (int i = 0; i < 4; i++) {
        workers.emplace_back(process_client_requests, ssl_ctx);
    }

    // epoll 인스턴스 생성
    int epoll_fd = epoll_create1(0); // epoll_fd 선언 및 초기화
    if (epoll_fd == -1) {
        perror("[ERROR] epoll 인스턴스 생성 실패");
        close(http_socket);
        close(https_socket);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    struct epoll_event event{};
    event.events = EPOLLIN;

    // HTTP 소켓 epoll 등록
    event.data.fd = http_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, http_socket, &event) == -1) {
        perror("[ERROR] HTTP 소켓 epoll 등록 실패");
        close(http_socket);
        close(https_socket);
        close(epoll_fd);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    // HTTPS 소켓 epoll 등록
    event.data.fd = https_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, https_socket, &event) == -1) {
        perror("[ERROR] HTTPS 소켓 epoll 등록 실패");
        close(http_socket);
        close(https_socket);
        close(epoll_fd);
        SSL_CTX_free(ssl_ctx);
        return EXIT_FAILURE;
    }

    vector<struct epoll_event> events(MAX_EVENTS);

    // epoll을 통해 클라이언트 요청 처리
    while (true) {
        int event_count = epoll_wait(epoll_fd, events.data(), MAX_EVENTS, -1);
        if (event_count == -1) {
            perror("[ERROR] epoll 대기 실패");
            break;
        }

        for (int i = 0; i < event_count; i++) {
            int event_fd = events[i].data.fd;

            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(event_fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_fd == -1) {
                perror("[ERROR] 클라이언트 연결 실패");
                continue;
            }

            cerr << "[INFO] 클라이언트 연결 성공 (FD: " << client_fd << ")" << endl;

            // 클라이언트 큐에 추가
            {
                lock_guard<mutex> lock(queue_mutex);
                bool use_ssl = (event_fd == https_socket);
                client_queue.emplace(client_fd, use_ssl);
            }
            queue_cv.notify_one();
        }
    }

    // 리소스 정리
    for (auto& worker : workers) {
        if (worker.joinable())
            worker.join();
    }
    close(http_socket);
    close(https_socket);
    close(epoll_fd);
    SSL_CTX_free(ssl_ctx);

    return 0;
}

