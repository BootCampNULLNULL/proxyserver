#include "server_side.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sstream>

std::string forward_to_server(const std::string& request) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Socket creation failed");
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80); // Default HTTP port

    std::string host = extract_host_from_request(request);
    inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);

    if (connect(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connection to server failed");
        close(server_fd);
        return "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    }

    send(server_fd, request.c_str(), request.length(), 0);

    char buffer[BUFFER_SIZE];
    std::stringstream response;
    int bytes;

    while ((bytes = recv(server_fd, buffer, sizeof(buffer), 0)) > 0) { // 수정: 4번째 인자 추가
        response.write(buffer, bytes);
    }

    close(server_fd);
    return response.str();
}

std::string extract_host_from_request(const std::string& request) {
    std::string host_header = "Host: ";
    auto start = request.find(host_header) + host_header.length();
    auto end = request.find("\r\n", start);
    return request.substr(start, end - start);
}

