#ifndef SSL_CONN
#define SSL_CONN
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

void initialize_openssl();
void cleanup_openssl();
void handle_openssl_error();
EVP_PKEY *load_private_key(const char *key_file);
X509 *load_certificate(const char *cert_file);
EVP_PKEY *generate_rsa_key();
X509* generate_cert(const char* domain, EVP_PKEY* key, X509* ca_cert, EVP_PKEY* ca_key);
int save_cert_and_key(X509 *cert, EVP_PKEY *key, const char *cert_path, const char *key_path);
SSL* handle_client_SSL_conn(int client_sock, 
char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX* client_ctx);
SSL* client_proxy_SSL_conn(int cfd, SSL_CTX** ctx);
int make_ssl_cert(const char* domain, EVP_PKEY *ca_key, X509 *ca_cert);
SSL* handle_client_SSL_conn2(SSL* ssl, char* domain, int port, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX** client_ctx);
int setup_ssl_cert(char* domain, EVP_PKEY *ca_key, X509 *ca_cert, SSL_CTX** ctx, SSL** ssl);
#endif //SSL_CONN
