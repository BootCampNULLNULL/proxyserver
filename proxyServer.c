#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 1234
#define BUFFER_SIZE 100000

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}


void cleanup_openssl() {
    EVP_cleanup();
}


SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 

int OpenConnection(const char *hostname, int port)
{   
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr_list[0]);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}


void tunnel_data(int client_sock, int remote_sock) {
    fd_set fds;
    char buffer[BUFFER_SIZE];
    int max_fd = (client_sock > remote_sock ? client_sock : remote_sock) + 1;

    while (1) {
        FD_ZERO(&fds);
        FD_SET(client_sock, &fds);
        FD_SET(remote_sock, &fds);

        if (select(max_fd, &fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(client_sock, &fds)) {
            int bytes = recv(client_sock, buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) break; // 클라이언트 종료
            send(remote_sock, buffer, bytes, 0);
        }

        if (FD_ISSET(remote_sock, &fds)) {
            int bytes = recv(remote_sock, buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) break; // 원격 서버 종료
            send(client_sock, buffer, bytes, 0);
        }
    }
}


void handle_client(int client_sock, SSL_CTX *ctx) {
    char buffer[BUFFER_SIZE];
    SSL *ssl;
    int bytes = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) {
        close(client_sock);
        return;
    }
    buffer[bytes] = '\0';
    printf("%s\n",buffer);


    // Parse CONNECT request
    char method[16], host[256];
    int port = 443;
    if (sscanf(buffer, "%15s %255[^:]:%d", method, host, &port) != 3) {
        const char *bad_request = "HTTP/1.1 400 Bad Request\r\n\r\n";
        send(client_sock, bad_request, strlen(bad_request), 0);
        close(client_sock);
        return;
    }

    printf("CONNECT to %s:%d\n", host, port);

    // Connect to the remote server
    int remote_sock = OpenConnection(host, port);
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, remote_sock);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == -1 )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {  
        char acClientRequest[1000]={0,};
        char buf[100000]={0,};
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        // sprintf(acClientRequest, "GET / HTTP/1.1\r\nHost: www.naver.com\r\nConnection: close\r\n\r\n");
        if(!strcmp(method,"CONNECT")){
            sprintf(buf,"HTTP/1.0 200 Connection established\r\n\r\n");
            bytes = strlen(buf);
            send(client_sock, buf, bytes, 0);
            SSL_free(ssl);
            close(remote_sock);         /* close socket */
            SSL_CTX_free(ctx);        /* release context */
            return;
        }
        else{
            sprintf(acClientRequest,buffer);
        }
        printf("%s\n",acClientRequest);
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: %s\n", buf);
        
        send(client_sock, buf, bytes, 0);

        SSL_free(ssl);        /* release connection state */

    }
    
    close(remote_sock);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
}

int main() {
    initialize_openssl();
    SSL_CTX *ctx = InitCTX();

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 10) < 0) {
        perror("listen");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("Proxy server running on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        int client_port = ntohs(client_addr.sin_port);

        printf("Client connected: IP=%s, Port=%d\n", client_ip, client_port);

        handle_client(client_sock, ctx);
    }

    close(server_sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}
