#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include "ssl_conn.h"
#include "errcode.h"

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// OpenSSL 정리
void cleanup_openssl() {
    EVP_cleanup();
}

// OpenSSL 초기화
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

/**
 * @brief 키, SSL 인증서 생성 및 SSL 객체에 연결
 * 
 * @param domain SSL 인증서에 적용할 도메인
 * @param ca_key 
 * @param ca_cert 
 * @param ctx OUT ssl 인증서,키를 연결한 SSL_CTX
 * @param ssl OUT SSL_CTX를 연결한 SSL
 * @return int 
 * 성공(0), 실패(others)
 */
int setup_ssl_cert(char* domain, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX** ctx, SSL** ssl)
{
    // 동적 키 생성 및 인증서 생성
    EVP_PKEY *key = generate_rsa_key();
    if (!key) {
        perror("Failed to generate RSA key");
        return -1;
    }

    X509 *dynamic_cert = generate_cert(domain, key, ca_cert, ca_key);
    if (!dynamic_cert) {
        EVP_PKEY_free(key);
        perror("Failed to generate dynamic certificate");
        return -1;
    }
    
    const char *cert_file = "/home/sgseo/proxyserver/dynamic_cert.pem";
    const char *key_file = "/home/sgseo/proxyserver/dynamic_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return -1;
    }

    // SSL 컨텍스트 생성
    *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(*ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(*ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(*ctx, "HIGH:!aNULL:!MD5:!RC4");

    if (!SSL_CTX_use_certificate_file(*ctx, cert_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        SSL_CTX_free(*ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return -1;
    }

    if (!SSL_CTX_use_PrivateKey_file(*ctx, key_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        SSL_CTX_free(*ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return -1;
    }

    *ssl = SSL_new(*ctx);
    return STAT_OK;
}

SSL* handle_client_SSL_conn(int client_sock, 
char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX* client_ctx) {
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
    
    const char *cert_file = "/home/sgseo/proxyserver/dynamic_cert.pem";
    const char *key_file = "/home/sgseo/proxyserver/dynamic_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    // SSL 컨텍스트 생성
    client_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(client_ctx, "HIGH:!aNULL:!MD5:!RC4");

    if (!SSL_CTX_use_certificate_file(client_ctx, cert_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(client_ctx, key_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        close(client_sock);
        return NULL;
    }

    SSL *ssl = SSL_new(client_ctx);
    SSL_set_fd(ssl, client_sock);

    X509_free(dynamic_cert);
    EVP_PKEY_free(key);

    return ssl;
    
}



SSL* handle_client_SSL_conn2(SSL* ssl, char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX** client_ctx) {
    //
    const char *response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    SSL_write(ssl, response, strlen(response));

    // 동적 키 생성 및 인증서 생성
    EVP_PKEY *key = generate_rsa_key();
    if (!key) {
        perror("Failed to generate RSA key");
        return NULL;
    }

    X509 *dynamic_cert = generate_cert(domain, key, ca_cert, ca_key);
    if (!dynamic_cert) {
        EVP_PKEY_free(key);
        perror("Failed to generate dynamic certificate");
        return NULL;
    }
    
    const char *cert_file = "/home/sgseo/proxyserver/dynamic_cert.pem";
    const char *key_file = "/home/sgseo/proxyserver/dynamic_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return NULL;
    }

    // SSL 컨텍스트 생성
    client_ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(client_ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION);
    SSL_CTX_set_cipher_list(client_ctx, "HIGH:!aNULL:!MD5:!RC4");

    if (!SSL_CTX_use_certificate_file(client_ctx, cert_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(client_ctx, key_file, SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        SSL_CTX_free(client_ctx);
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return NULL;
    }

    SSL *ssl2 = SSL_new(client_ctx);
    return ssl2;
    
}

int make_ssl_cert(const char* domain, EVP_PKEY *ca_key, X509 *ca_cert) {
    // 동적 키 생성 및 인증서 생성
    EVP_PKEY *key = generate_rsa_key();
    if (!key) {
        perror("Failed to generate RSA key");
        return -1;
    }

    X509 *dynamic_cert = generate_cert(domain, key, ca_cert, ca_key);
    if (!dynamic_cert) {
        EVP_PKEY_free(key);
        perror("Failed to generate dynamic certificate");
        return -2;
    }
    
    const char *cert_file = "/home/sgseo/proxyserver/proxy_cert.pem";
    const char *key_file = "/home/sgseo/proxyserver/proxy_key.pem";

    if (!save_cert_and_key(dynamic_cert, key, cert_file, key_file)) {
        EVP_PKEY_free(key);
        X509_free(dynamic_cert);
        return -3;
    }
    return 0;
}


SSL* client_proxy_SSL_conn(int cfd, SSL_CTX** ctx) {
    
    // SSL 컨텍스트 생성
    *ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_use_certificate_file(*ctx, "/home/new/proxyserver/proxy_cert.pem", SSL_FILETYPE_PEM)) {
        perror("Failed to load certificate from file");
        return NULL;
    }

    if (!SSL_CTX_use_PrivateKey_file(*ctx, "/home/new/proxyserver/proxy_key.pem", SSL_FILETYPE_PEM)) {
        perror("Failed to load private key from file");
        return NULL;
    }

    SSL *ssl = SSL_new(*ctx);
    SSL_set_fd(ssl, cfd);

    return ssl;
    
}

// SSL* client_proxy_SSL_conn(const char* buffer, int buffer_size, SSL_CTX** ssl_ctx, BIO** rbio, BIO** wbio){
//     *ssl_ctx = SSL_CTX_new(TLS_server_method());
//     SSL* ssl = SSL_new(ssl_ctx);
//     *rbio = BIO_new(BIO_s_mem()); //읽기용 BIO
//     *wbio = BIO_new(BIO_s_mem()); //쓰기용 BIO
//     SSL_set_bio(ssl, *rbio, *wbio);
//     BIO_write(*rbio, buffer, buffer_size);
//     int ret = SSL_do_handshake(ssl);
//     if (ret > 0) {
//         printf("SSL 핸드쉐이크 성공!\n");
//         return ssl;
//     }
//     int err = SSL_get_error(ssl, ret);
//     if (err == SSL_ERROR_WANT_READ) {
//         char outbuffer[MAX_BUFFER_SIZE];
//         int outbytes = BIO_read(wbio, outbuffer, sizeof(outbuffer));
//         if (outbytes > 0) {
//             int bytes = SSL_write(ssl, outbuffer, outbytes);
//         }
//         char buffer[MAX_BUFFER_SIZE] = {0,};
//         int bytes = SSL_read(proxy_client_ssl, buffer, sizeof(buffer) - 1);
//         BIO_write(rbio, buffer, bytes); // 읽은 데이터를 Read BIO에 씀
//         continue;
//     } else if(err == SSL_ERROR_WANT_WRITE){
//         char buffer[MAX_BUFFER_SIZE];
//         int bytes = BIO_read(wbio, buffer, sizeof(buffer));
//         if (bytes > 0) {
//             SSL_write(proxy_client_ssl, buffer, sizeof(buffer));
//         }
//     }
//     else {
//         // 기타 에러 처리
//         printf("SSL_accept 실패. 에러 코드: %d\n", err);
//         ERR_print_errors_fp(stderr);
//         return -1;
//     }
// } 


