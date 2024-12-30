#include "logger.h"
#include <fstream>
#include <ctime>

using namespace std;

/**
 * @brief 클라이언트 요청 및 응답을 로그에 기록하는 함수
 *
 * 요청/응답 정보를 `access.log` 파일에 기록합니다.
 *
 * @param client_fd 클라이언트 소켓 파일 디스크립터
 * @param request 클라이언트 HTTP 요청 문자열
 */
void log_request(int client_fd, const string& request) {
    ofstream log_file("access.log", ios::app);  // 로그 파일을 append 모드로 열기
    if (!log_file.is_open()) return;

    // 현재 시간 기록
    time_t now = time(nullptr);
    log_file << "[" << ctime(&now) << "] "
             << "Client FD: " << client_fd
             << ", Request: " << request << endl;

    log_file.close();  // 파일 닫기
}
