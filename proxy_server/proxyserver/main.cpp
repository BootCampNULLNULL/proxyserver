#include "client_side.h"
#include "make_cert.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>

#define PROXY_PORT 8080

int main() {
    SSL_CTX* ssl_ctx = initialize_ssl("proxy_cert.pem", "proxy_key.pem");

    int proxy_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_fd == -1) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in proxy_addr{};
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_addr.s_addr = INADDR_ANY;
    proxy_addr.sin_port = htons(PROXY_PORT);

    if (bind(proxy_fd, (struct sockaddr*)&proxy_addr, sizeof(proxy_addr)) == -1) {
        perror("Bind failed");
        close(proxy_fd);
        return -1;
    }

    if (listen(proxy_fd, SOMAXCONN) == -1) {
        perror("Listen failed");
        close(proxy_fd);
        return -1;
    }

    std::cout << "Proxy server running on port " << PROXY_PORT << std::endl;

    while (true) {
        int client_fd = accept(proxy_fd, nullptr, nullptr);
        if (client_fd == -1) {
            perror("Accept failed");
            continue;
        }

        handle_client(client_fd, ssl_ctx);
    }

    close(proxy_fd);
    SSL_CTX_free(ssl_ctx);
    return 0;
}
