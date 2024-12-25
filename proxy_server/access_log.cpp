#include "access_log.h"
#include <fstream>
#include <ctime>

void log_access(int client_fd, const std::string& request) {
    std::ofstream log_file("access.log", std::ios::app);
    if (!log_file.is_open()) return;

    time_t now = time(nullptr);
    log_file << "[" << std::ctime(&now) << "] "
             << "Client FD: " << client_fd
             << ", Request: " << request << std::endl;

    log_file.close();
}
