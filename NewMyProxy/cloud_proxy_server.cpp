#include <iostream>
#include <thread>
#include <vector>
#include <unordered_set>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>

// Configuration constants
const int MAX_EVENTS = 1024;
const int THREAD_POOL_SIZE = 4;
const char* SERVER_CERT = "/home/abc/NewMyProxy/server.crt";
const char* SERVER_KEY = "/home/abc/NewMyProxy/server.key";
const std::unordered_set<std::string> BLOCKED_SITES = {"malicious.com", "example-bad.com"};

// Function prototypes
void handle_client(int client_fd, SSL_CTX* ctx);
void setup_ssl(SSL_CTX*& ctx);
void set_non_blocking(int sock);
void log_request(const std::string& ip);
bool is_blocked_site(const std::string& host);
bool forward_https_request(const std::string& host, SSL* client_ssl);
bool forward_http_request(const std::string& host, SSL* client_ssl);

// Entry point
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>\n";
        return 1;
    }

    int server_port = std::stoi(argv[1]);
    SSL_CTX* ctx = nullptr;
    setup_ssl(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("socket");
        return 1;
    }

    set_non_blocking(server_fd);

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(server_port);

    if (bind(server_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        close(server_fd);
        return 1;
    }

    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) == -1) {
        perror("epoll_ctl");
        close(server_fd);
        close(epoll_fd);
        return 1;
    }

    std::vector<std::thread> thread_pool;
    for (int i = 0; i < THREAD_POOL_SIZE; ++i) {
        thread_pool.emplace_back([epoll_fd, ctx, server_fd]() {
            epoll_event ev{};
            epoll_event events[MAX_EVENTS];

            while (true) {
                int event_count = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
                for (int i = 0; i < event_count; ++i) {
                    if (events[i].data.fd == server_fd) {
                        sockaddr_in client_addr;
                        socklen_t client_len = sizeof(client_addr);
                        int client_fd = accept(server_fd, (sockaddr*)&client_addr, &client_len);

                        if (client_fd == -1) {
                            perror("accept");
                            continue;
                        }

                        set_non_blocking(client_fd);

                        ev.events = EPOLLIN | EPOLLET;
                        ev.data.fd = client_fd;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    } else {
                        handle_client(events[i].data.fd, ctx);
                    }
                }
            }
        });
    }

    for (auto& thread : thread_pool) {
        thread.join();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

void handle_client(int client_fd, SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        return;
    }

    char buffer[4096];
    int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        std::string request(buffer);

        size_t host_start = request.find("Host: ");
        if (host_start != std::string::npos) {
            host_start += 6;
            size_t host_end = request.find("\r\n", host_start);
            std::string host = request.substr(host_start, host_end - host_start);

            log_request(host);

            if (is_blocked_site(host)) {
                std::string response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
                SSL_write(ssl, response.c_str(), response.size());
            } else {
                if (!forward_https_request(host, ssl)) {
                    std::string response = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
                    SSL_write(ssl, response.c_str(), response.size());
                }
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
}

bool forward_https_request(const std::string& host, SSL* client_ssl) {
    SSL_CTX* forward_ctx = SSL_CTX_new(TLS_client_method());
    if (!forward_ctx) {
        ERR_print_errors_fp(stderr);
        return false;
    }

    SSL* forward_ssl = SSL_new(forward_ctx);
    if (!forward_ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(forward_ctx);
        return false;
    }

    int forward_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (forward_fd == -1) {
        perror("socket");
        SSL_free(forward_ssl);
        SSL_CTX_free(forward_ctx);
        return false;
    }

    hostent* server = gethostbyname(host.c_str());
    if (!server) {
        perror("gethostbyname");
        close(forward_fd);
        SSL_free(forward_ssl);
        SSL_CTX_free(forward_ctx);
        return false;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    std::memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    server_addr.sin_port = htons(443); // HTTPS port

    if (connect(forward_fd, (sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("connect");
        close(forward_fd);
        SSL_free(forward_ssl);
        SSL_CTX_free(forward_ctx);
        return false;
    }

    SSL_set_fd(forward_ssl, forward_fd);
    if (SSL_connect(forward_ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(forward_fd);
        SSL_free(forward_ssl);
        SSL_CTX_free(forward_ctx);
        return false;
    }

    char buffer[4096];
    int bytes_read = SSL_read(client_ssl, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        SSL_write(forward_ssl, buffer, bytes_read);
        bytes_read = SSL_read(forward_ssl, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            SSL_write(client_ssl, buffer, bytes_read);
        }
    }

    SSL_shutdown(forward_ssl);
    close(forward_fd);
    SSL_free(forward_ssl);
    SSL_CTX_free(forward_ctx);
    return true;
}

void setup_ssl(SSL_CTX*& ctx) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
}

void set_non_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void log_request(const std::string& ip) {
    std::cout << "Request from IP: " << ip << std::endl;
}

bool is_blocked_site(const std::string& host) {
    return BLOCKED_SITES.find(host) != BLOCKED_SITES.end();
}
