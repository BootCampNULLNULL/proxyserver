#ifndef ACCESS_LOG_H
#define ACCESS_LOG_H

#include <string>

// 액세스 로그 기록
void log_access(int client_fd, const std::string& request);

#endif // ACCESS_LOG_H
