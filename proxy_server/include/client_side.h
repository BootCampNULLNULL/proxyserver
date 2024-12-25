// client_side.h
#ifndef CLIENT_SIDE_H
#define CLIENT_SIDE_H

#ifndef BUFFER_SIZE
#define BUFFER_SIZE 4096
#endif


#include <openssl/ssl.h>
#include <string>

void handle_client(int client_fd, SSL_CTX* ctx);

#endif // CLIENT_SIDE_H
