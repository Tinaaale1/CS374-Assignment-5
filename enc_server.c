#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>

#define MAX_MSG_SIZE 150000

// Helper function to check valid characters (A-Z and space)
int isValidChar(char c) {
    return (c == ' ' || (c >= 'A' && c <= 'Z'));
}

// Encryption function: modulo 27 (A-Z + space)
void encrypt(char *message, char *key, int length) {
    for (int i = 0; i < length; i++) {
        int msg_val = (message[i] == ' ') ? 26 : (message[i] - 'A');
        int key_val = (key[i] == ' ') ? 26 : (key[i] - 'A');
        int enc_val = (msg_val + key_val) % 27;
        message[i] = (enc_val == 26) ? ' ' : ('A' + enc_val);
    }
}

// Read from socket until newline or max_len-1 chars
ssize_t recv_until_newline(int sockfd, char *buf, size_t max_len) {
    size_t total = 0;
    while (total < max_len - 1) {
        char c;
        ssize_t n = recv(sockfd, &c, 1, 0);
        if (n <= 0) return n;  // error or closed
        if (c == '\n') break;
        buf[total++] = c;
    }
    buf[total] = '\0';
    return total;
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portno, pid;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;

    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("ERROR on accept");
            continue;
        }

        pid = fork();
        if (pid < 0) {
            perror("ERROR on fork");
            close(newsockfd);
            continue;
        }

        if (pid == 0) {
            close(sockfd);

            char clientAuth[20];
            ssize_t n = recv_until_newline(newsockfd, clientAuth, sizeof(clientAuth));
            if (n <= 0) {
                close(newsockfd);
                exit(1);
            }

            if (strcmp(clientAuth, "enc_d_bs") != 0) {
                char response[] = "invalid\n";
                write(newsockfd, response, strlen(response));
                close(newsockfd);
                exit(2);
            }

            char serverToken[] = "enc_d_bs\n";
            n = write(newsockfd, serverToken, strlen(serverToken));
            if (n < 0) {
                close(newsockfd);
                exit(1);
            }

            char message[MAX_MSG_SIZE];
            n = recv_until_newline(newsockfd, message, sizeof(message));
            if (n <= 0) {
                close(newsockfd);
                exit(1);
            }

            char key[MAX_MSG_SIZE];
            n = recv_until_newline(newsockfd, key, sizeof(key));
            if (n <= 0) {
                close(newsockfd);
                exit(1);
            }

            int msgLen = strlen(message);
            int keyLen = strlen(key);

            if (keyLen < msgLen) {
                char errorMsg[] = "Error: key too short\n";
                write(newsockfd, errorMsg, strlen(errorMsg));
                fprintf(stderr, "enc_server: ERROR - key shorter than message\n");
                close(newsockfd);
                exit(1);
            }

            for (int i = 0; i < msgLen; i++) {
                if (!isValidChar(message[i])) {
                    char errorMsg[] = "Error: invalid character in message\n";
                    write(newsockfd, errorMsg, strlen(errorMsg));
                    fprintf(stderr, "enc_server: ERROR - invalid character in message\n");
                    close(newsockfd);
                    exit(1);
                }
            }
            for (int i = 0; i < keyLen; i++) {
                if (!isValidChar(key[i])) {
                    char errorMsg[] = "Error: invalid character in key\n";
                    write(newsockfd, errorMsg, strlen(errorMsg));
                    fprintf(stderr, "enc_server: ERROR - invalid character in key\n");
                    close(newsockfd);
                    exit(1);
                }
            }

            encrypt(message, key, msgLen);

            // Send encrypted message plus newline
            write(newsockfd, message, msgLen);
            write(newsockfd, "\n", 1);

            close(newsockfd);
            exit(0);
        } else {
            close(newsockfd);
        }
    }
    close(sockfd);
    return 0;
}
