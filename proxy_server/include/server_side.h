#ifndef SERVER_SIDE_H
#define SERVER_SIDE_H

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif


#include <string>

// 서버 요청 전달 및 응답 수신
std::string forward_to_server(const std::string& request);

// 요청에서 호스트 추출
std::string extract_host_from_request(const std::string& request);

#endif // SERVER_SIDE_H
