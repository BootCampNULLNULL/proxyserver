#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}
//
int BAKmain() {
    // 1. RSA 키 생성
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) handle_openssl_error();

    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (!rsa) handle_openssl_error();

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) handle_openssl_error();

    // 2. X509 인증서 객체 생성
    X509 *x509 = X509_new();
    if (!x509) handle_openssl_error();

    // 3. 인증서 유효 기간 설정
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60L);
//
    // 4. 인증서의 공개 키 설정
    if (X509_set_pubkey(x509, pkey) != 1) handle_openssl_error();

    // 5. 인증서 이름 설정
    X509_NAME *name = X509_get_subject_name(x509);
    if (!name) handle_openssl_error();

    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)"MyOrganization", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"MyCertificate", -1, -1, 0);

    // 발급자 이름 설정 (자체 서명된 인증서이므로 동일하게 설정)
    if (X509_set_issuer_name(x509, name) != 1) handle_openssl_error();

    // 6. 인증서 서명
    if (X509_sign(x509, pkey, EVP_sha256()) == 0) handle_openssl_error();

    // 7. 인증서 및 키 저장
    FILE *cert_file = fopen("certificate.pem", "wb");
    if (!cert_file) {
        perror("Failed to open certificate.pem");
        exit(EXIT_FAILURE);
    }
    PEM_write_X509(cert_file, x509);
    fclose(cert_file);

    FILE *key_file = fopen("private_key.pem", "wb");
    if (!key_file) {
        perror("Failed to open private_key.pem");
        exit(EXIT_FAILURE);
    }
    PEM_write_PrivateKey(key_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(key_file);

    // 8. 메모리 정리
    X509_free(x509);
    EVP_PKEY_free(pkey);

    printf("Certificate and private key have been generated.\n");
    return 0;
}
