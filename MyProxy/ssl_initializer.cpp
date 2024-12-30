#include "ssl_initializer.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>

using namespace std;

SSL_CTX* initialize_ssl_context(const string& ca_cert, const string& cert_file, const string& key_file) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "[ERROR] 인증서 파일 로드 실패: " << cert_file << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        cerr << "[ERROR] 개인 키 파일 로드 실패: " << key_file << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        cerr << "[ERROR] 인증서와 키가 일치하지 않음" << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_load_verify_locations(ctx, ca_cert.c_str(), nullptr)) {
        cerr << "[ERROR] CA 인증서 로드 실패: " << ca_cert << endl;
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    cerr << "[INFO] SSL 컨텍스트 초기화 성공" << endl;
    return ctx;
}

