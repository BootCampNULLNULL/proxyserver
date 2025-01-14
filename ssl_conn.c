#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "ssl_conn.h"

// OpenSSL 초기화
void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// OpenSSL 정리
void cleanup_openssl() {
    EVP_cleanup();
}

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// 키 및 인증서 로드
EVP_PKEY *load_private_key(const char *key_file) {
    FILE *fp = fopen(key_file, "r");
    if (!fp) {
        perror("Unable to open CA key file");
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return key;
}

X509 *load_certificate(const char *cert_file) {
    FILE *fp = fopen(cert_file, "r");
    if (!fp) {
        perror("Unable to open CA cert file");
        return NULL;
    }
    X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

// RSA 키 생성
EVP_PKEY *generate_rsa_key() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        fprintf(stderr, "Failed to allocate EVP_PKEY\n");
        handle_openssl_error();
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Failed to create RSA object\n");
        EVP_PKEY_free(pkey);
        handle_openssl_error();
    }

    BIGNUM *bn = BN_new();
    if (!bn || !BN_set_word(bn, RSA_F4)) {
        fprintf(stderr, "Failed to set RSA_F4 exponent\n");
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    if (RSA_generate_key_ex(rsa, 2048, bn, NULL) <= 0) {
        fprintf(stderr, "Failed to generate RSA key\n");
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) <= 0) {
        fprintf(stderr, "Failed to assign RSA to EVP_PKEY\n");
        RSA_free(rsa); // This frees `rsa` since EVP_PKEY_assign_RSA failed
        EVP_PKEY_free(pkey);
        BN_free(bn);
        handle_openssl_error();
    }

    BN_free(bn);
    return pkey;
}

// 특정 도메인에 대한 인증서 생성성
X509* generate_cert(const char* domain, EVP_PKEY* key, X509* ca_cert, EVP_PKEY* ca_key) {
    // 새로운 X.509 인증서 구조체 할당
    X509* cert = X509_new();
    if (!cert) handle_openssl_error();

    // 인증서 버전 설정
    X509_set_version(cert, 2);
    // 인증서 고유 일련 번호 설정
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // 인증서 유효기간 설정
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    // 인증서 주체이름 설정
    X509_NAME* name = X509_get_subject_name(cert);
    // 주체 이름에 도메인 정보 추가
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)domain, -1, -1, 0);
    // 인증서에 적용
    X509_set_subject_name(cert, name);

    // 
    X509_EXTENSION *san = X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, domain);
    if (san) {
        X509_add_ext(cert, san, -1);
        X509_EXTENSION_free(san);
    }

    // 인증서 발급자(issuer) 이름 설정 --> 루트 CA 인증서 사용
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert));
    
    // 인증서에 사용할 공개 키 설정
    X509_set_pubkey(cert, key);

    // 루트CA 개인키로 암호화하여 디지털 서명 생성
    if (!X509_sign(cert, ca_key, EVP_sha256())) {
        X509_free(cert);
        handle_openssl_error();
    }
    
    // 
    return cert;
}


// 인증서 및 키 저장 함수
int save_cert_and_key(X509 *cert, EVP_PKEY *key, const char *cert_path, const char *key_path) {
    FILE *cert_file = fopen(cert_path, "wb");
    if (!cert_file) {
        perror("Failed to open certificate file");
        return 0;
    }

    if (!PEM_write_X509(cert_file, cert)) {
        perror("Failed to write certificate to file");
        fclose(cert_file);
        return 0;
    }
    fclose(cert_file);

    FILE *key_file = fopen(key_path, "wb");
    if (!key_file) {
        perror("Failed to open private key file");
        return 0;
    }

    if (!PEM_write_PrivateKey(key_file, key, NULL, NULL, 0, NULL, NULL)) {
        perror("Failed to write private key to file");
        fclose(key_file);
        return 0;
    }
    fclose(key_file);

    return 1;
}

// 클라이언트 요청 처리 (수정)
SSL* handle_client_SSL_conn(int client_sock, 
char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert) {
    
    // 
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    send(client_sock, response, strlen(response), 0);

    // 동적 키 생성 및 인증서 생성
    EVP_PKEY *key = generate_rsa_key();
    if (!key) {
        perror("Failed to generate RSA key");
        close(client_sock);
        return NULL;
    }

    X509 *dynamic_cert = generate_cert(domain, key, ca_cert, ca_key);
    if (!dynamic_cert) {
        EVP_PKEY_free(key);
        perror("Failed to generate dynamic certificate");
        close(client_sock);
        return NULL;
    }

    const char *cert_file = "/home/ubuntu/securezone/dynamic_cert.pem";
    const char *key_file = "/home/ubuntu/securezone/dynamic_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    // SSL 컨텍스트 생성
    SSL_CTX *dynamic_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(dynamic_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(dynamic_ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(dynamic_ctx, "HIGH:!aNULL:!MD5:!RC4");

    if (!SSL_CTX_use_certificate_file(dynamic_ctx, cert_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        SSL_CTX_free(dynamic_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(dynamic_ctx, key_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        SSL_CTX_free(dynamic_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    SSL *ssl = SSL_new(dynamic_ctx);
    SSL_set_fd(ssl, client_sock);

    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        int err = SSL_get_error(ssl, -1);

        switch (err) {
            case SSL_ERROR_NONE:
                printf("No error occurred.\n");
                break;
            case SSL_ERROR_ZERO_RETURN:
                printf("Client closed the connection.\n");
                break;
            case SSL_ERROR_WANT_READ:
                printf("SSL_accept needs more data (WANT_READ).\n");
                break;
            case SSL_ERROR_WANT_WRITE:
                printf("SSL_accept needs to write more data (WANT_WRITE).\n");
                break;
            case SSL_ERROR_SYSCALL:
                perror("System call error during SSL_accept");
                break;
            case SSL_ERROR_SSL:
                printf("OpenSSL internal error occurred.\n");
                ERR_print_errors_fp(stderr);
                break;
            default:
                printf("Unknown error occurred: %d\n", err);
                break;
        }
        SSL_free(ssl);
        SSL_CTX_free(dynamic_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    } 
    return ssl;
    // SSL_free(ssl);
    // SSL_CTX_free(dynamic_ctx);
    // EVP_PKEY_free(key);
    // X509_free(dynamic_cert);
    // close(client_sock);
}


// int main() {

//     const char *cert_file = CERT_FILE;
//     const char *key_file = KEY_FILE;

//     initialize_openssl();

//     EVP_PKEY *ca_key = load_private_key(key_file);
//     X509 *ca_cert = load_certificate(cert_file);
//     if (!ca_key || !ca_cert) {
//         fprintf(stderr, "Failed to load CA key or certificate\n");
//         exit(EXIT_FAILURE);
//     }

//     int server_sock = socket(AF_INET, SOCK_STREAM, 0);
//     if (server_sock < 0) {
//         perror("Unable to create socket");
//         exit(EXIT_FAILURE);
//     }

//     struct sockaddr_in addr;
//     addr.sin_family = AF_INET;
//     addr.sin_port = htons(5052);
//     addr.sin_addr.s_addr = INADDR_ANY;

//     if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
//         perror("Unable to bind");
//         close(server_sock);
//         exit(EXIT_FAILURE);
//     }

//     if (listen(server_sock, 10) < 0) {
//         perror("Unable to listen");
//         close(server_sock);
//         exit(EXIT_FAILURE);
//     }

//     printf("Listening on port 5052...\n");

//     while (1) {
//         struct sockaddr_in client_addr;
//         socklen_t client_len = sizeof(client_addr);
//         int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
//         if (client_sock < 0) {
//             perror("Unable to accept");
//             continue;
//         }

//         handle_client_with_dynamic_cert(client_sock, ca_key, ca_cert);
//     }

//     close(server_sock);
//     EVP_PKEY_free(ca_key);
//     X509_free(ca_cert);
//     cleanup_openssl();

//     return 0;
// }
