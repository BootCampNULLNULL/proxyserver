#include "security_checker.h"
#include <string>

using namespace std;

/**
 * @brief 요청이 보안 정책을 위반하는지 확인하는 함수
 *
 * 요청 문자열에서 차단된 도메인 또는 불허된 요청 패턴을 확인합니다.
 *
 * @param request 클라이언트 HTTP 요청 문자열
 * @return bool 정책 위반이면 true, 아니면 false
 */
bool is_policy_violation(const string& request) {
    // 예: "blocked.com" 도메인이 요청에 포함되어 있다면 차단
    if (request.find("blocked.com") != string::npos) {
        return true;
    }
    return false;
}
