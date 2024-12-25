#include "make_cert.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX* initialize_ssl(const std::string& cert_file, const std::string& key_file) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
