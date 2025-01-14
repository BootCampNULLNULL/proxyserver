#ifndef SSL_CONN_H
#define SSL_CONN_H

#define BUFFER_SIZE 4096 // 버퍼 크기 정의
#define CERT_FILE "/home/ubuntu/securezone/certificate.pem" // 인증서 파일 경로
#define KEY_FILE  "/home/ubuntu/securezone/private_key.pem"  // 키 파일 경로

void initialize_openssl();
void cleanup_openssl();
EVP_PKEY *load_private_key(const char *key_file);
X509 *load_certificate(const char *cert_file);
X509* generate_cert(const char* domain, EVP_PKEY* key, X509* ca_cert, EVP_PKEY* ca_key);
int save_cert_and_key(X509 *cert, EVP_PKEY *key, const char *cert_path, const char *key_path);
SSL* handle_client_SSL_conn(int client_sock, char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert);

#endif
