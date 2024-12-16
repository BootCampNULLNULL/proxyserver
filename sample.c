#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVERPORT 5051

int main(void) {
        int sock_fd, new_fd, bytes, len;
        struct sockaddr_in seraddr, cliaddr;
        char data[1024];
        printf("dd\n");
        //listen socket open
        sock_fd = socket(AF_INET, SOCK_STREAM, 0);

        memset(&seraddr, 0, sizeof(seraddr));
        seraddr.sin_family = AF_INET;
        seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
        seraddr.sin_port = htons(SERVERPORT);
        if(bind(sock_fd, (struct sockaddr*)&seraddr, sizeof(seraddr)) < 0) {
                perror("Bind failed");
                close(sock_fd);
                exit(EXIT_FAILURE);
        }

        listen(sock_fd, 10);
        len = sizeof(cliaddr);
        while(1) {
                //client socket open
                new_fd = accept(sock_fd, (struct sockaddr*)&cliaddr, &len);
                memset(&data, 0, sizeof(data));
                bytes = recv(new_fd, data, 1024, 0);    //http reqeust -> data buffer
                //read_request_line(data);

                //remote socket open
                int sock_remote_fd;
                char response[1024];
                struct sockaddr_in remoteaddr;
                sock_remote_fd = socket(AF_INET, SOCK_STREAM, 0);

                memset(&remoteaddr, 0, sizeof(remoteaddr));
                remoteaddr.sin_family = AF_INET;
                remoteaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
                remoteaddr.sin_port = htons(8080);

                //remote server connect
                connect(sock_remote_fd, (struct sockaddr*)&remoteaddr, sizeof(remoteaddr));
                send(sock_remote_fd, data, strlen(data), 0);    //send data -> http reqeust
                printf("send complete\n");
                recv(sock_remote_fd, response, 1024, 0);        //recv http response -> response buffer
                printf("%s\n", response);
                //printf("%s\n", response);

                send(new_fd, response, 1024, 0);                //send response to client


                close(sock_remote_fd);
                close(new_fd);
        }

        close(sock_fd);
}
