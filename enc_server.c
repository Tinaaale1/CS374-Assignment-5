#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>   // For sockaddr_in and htons
#include <arpa/inet.h>    // For inet_addr, not mandatory here but often used
#include <sys/wait.h>     // For waitpid and handling child processes
#include <signal.h>       // For signal handling (optional but useful)
#define MAX_MSG_SIZE 150000

// Helper function to check valid characters (A-Z and space)
int isValidChar(char c) {
    return (c == ' ' || (c >= 'A' && c <= 'Z'));
}

// Encryption function: uses modulo 27 for A-Z + space
void encrypt(char *message, char *key, int length) {
    for (int i = 0; i < length; i++) {
        int msg_val = (message[i] == ' ') ? 26 : (message[i] - 'A');
        int key_val = (key[i] == ' ') ? 26 : (key[i] - 'A');
        int enc_val = (msg_val + key_val) % 27;
        message[i] = (enc_val == 26) ? ' ' : ('A' + enc_val);
    }
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portno, pid;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    char buffer[MAX_MSG_SIZE];
    char message[MAX_MSG_SIZE];
    char key[MAX_MSG_SIZE];
    char clientAuth[10];
    ssize_t n;

    // Check usage & args
    if (argc < 2) {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    // Initialize socket structure
    memset((char *)&serv_addr, 0, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    // Bind socket to port
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    // Start listening for connections
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    // Accept connections forever
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

        if (pid == 0) {  // Child process

            // Close listening socket in child
            close(sockfd);

            // Receive client authentication string
            memset(clientAuth, 0, sizeof(clientAuth));
            n = recv(newsockfd, clientAuth, sizeof(clientAuth) - 1, 0);
            if (n < 0) {
                perror("ERROR reading from socket");
                close(newsockfd);
                exit(1);
            }
            // Strip newline or trailing chars if any
            clientAuth[strcspn(clientAuth, "\r\n")] = 0;

            // Check for authentication token
            if (strcmp(clientAuth, "enc_bs") != 0) {
                // Send "invalid" response (without null terminator)
                char response[] = "invalid";
                write(newsockfd, response, strlen(response));
                close(newsockfd);
                exit(2);  // Exit code 2 for auth failure
            }

            // Send back server's handshake token
            char serverToken[] = "enc_d_bs";
            n = write(newsockfd, serverToken, strlen(serverToken));
            if (n < 0) {
                perror("ERROR writing to socket");
                close(newsockfd);
                exit(1);
            }

            // Receive plaintext message
            memset(message, 0, sizeof(message));
            n = recv(newsockfd, message, sizeof(message) - 1, 0);
            if (n < 0) {
                perror("ERROR reading message from socket");
                close(newsockfd);
                exit(1);
            }
            message[n] = '\0';  // Null-terminate

            // Receive key
            memset(key, 0, sizeof(key));
            n = recv(newsockfd, key, sizeof(key) - 1, 0);
            if (n < 0) {
                perror("ERROR reading key from socket");
                close(newsockfd);
                exit(1);
            }
            key[n] = '\0';  // Null-terminate

            // Remove trailing newlines if any
            message[strcspn(message, "\r\n")] = 0;
            key[strcspn(key, "\r\n")] = 0;

            int msgLen = strlen(message);
            int keyLen = strlen(key);

            // Check if key is shorter than message
            if (keyLen < msgLen) {
                char errorMsg[] = "Error: key too short\n";
                write(newsockfd, errorMsg, strlen(errorMsg));
                fprintf(stderr, "enc_server: ERROR - key shorter than message\n");
                close(newsockfd);
                exit(1);
            }

            // Validate message characters
            for (int i = 0; i < msgLen; i++) {
                if (!isValidChar(message[i])) {
                    char errorMsg[] = "Error: invalid character in message\n";
                    write(newsockfd, errorMsg, strlen(errorMsg));
                    fprintf(stderr, "enc_server: ERROR - invalid character in message\n");
                    close(newsockfd);
                    exit(1);
                }
            }

            // Validate key characters
            for (int i = 0; i < keyLen; i++) {
                if (!isValidChar(key[i])) {
                    char errorMsg[] = "Error: invalid character in key\n";
                    write(newsockfd, errorMsg, strlen(errorMsg));
                    fprintf(stderr, "enc_server: ERROR - invalid character in key\n");
                    close(newsockfd);
                    exit(1);
                }
            }

            // Perform encryption
            encrypt(message, key, msgLen);

            // Send encrypted message back to client followed by newline
            n = write(newsockfd, message, msgLen);
            if (n < 0) {
                perror("ERROR writing ciphertext to socket");
                close(newsockfd);
                exit(1);
            }
            // Send newline character to match expected output format
            write(newsockfd, "\n", 1);

            close(newsockfd);
            exit(0);  // Child exits successfully
        } else {
            // Parent closes the connected socket and continues
            close(newsockfd);
        }
    }

    // Close listening socket (though we never reach here)
    close(sockfd);
    return 0;
}
