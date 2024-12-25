#ifndef MAKE_CERT_H
#define MAKE_CERT_H

#include <openssl/ssl.h>
#include <string>

// SSL/TLS 초기화 및 컨텍스트 생성
SSL_CTX* initialize_ssl(const std::string& cert_file, const std::string& key_file);

#endif // MAKE_CERT_H
