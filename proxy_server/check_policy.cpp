#include "check_policy.h"

bool check_policy(const std::string& request) {
    if (request.find("blocked.com") != std::string::npos) {
        return false; // Block requests to "blocked.com"
    }
    return true;
}
