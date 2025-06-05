#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/wait.h>

#define BUFFER_SIZE 100000
#define MAX_CONNECTIONS 5

// Call errors and terminate the program
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Converts a character to its corresponding integer value 
int charToInt(char c) {
    if (c == ' ') {
        return 26;
    }
    return c - 'A';
}

// Converts an integer back to its corresponding character
char intToChar(int i) {
    if (i == 26) {
        return ' ';
    }
    return i + 'A';
}

// Checks if a character is valid (Uppercase or space)
int isValidChar(char c) {
    if (c == ' ') {
        return 1;
    }
    if (c >= 'A' && c <= 'Z') {
        return 1;
    }
    return 0;
}

// Decrypt message using key with OTP logic
void decrypt(char message[], char key[]) {
    int i;
    for (i = 0; message[i] != '\n' && message[i] != '\0'; i++) {
        int mVal = charToInt(message[i]);
        int kVal = charToInt(key[i]);
        int diff = mVal - kVal;
        if (diff < 0) {
            diff += 27;
        }
        message[i] = intToChar(diff);
    }
    message[i] = '\0'; // Null terminate decrypted message
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portnum, optval;
    socklen_t clientlen;
    struct sockaddr_in server_addr, client_addr;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("dec_server: ERROR opening socket");

    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

    memset(&server_addr, 0, sizeof(server_addr));
    portnum = atoi(argv[1]);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(portnum);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error("dec_server: ERROR on binding");

    listen(sockfd, MAX_CONNECTIONS);

    int activeConnections = 0;

    while (1) {
        clientlen = sizeof(client_addr);
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);

        if (newsockfd < 0) {
            fprintf(stderr, "dec_server: ERROR on accept\n");
            continue;
        }

        // Wait if too many active connections
        while (activeConnections >= MAX_CONNECTIONS) {
            pause(); // Wait for child to finish
        }

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "dec_server: ERROR forking\n");
            close(newsockfd);
            continue;
        }

        if (pid == 0) {
            // Child process
            close(sockfd);

            char buffer[BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));

            // --- Read authorization string ---
            char clientAuth[32];
            memset(clientAuth, 0, sizeof(clientAuth));
            ssize_t authRead = read(newsockfd, clientAuth, sizeof(clientAuth) - 1);
            if (authRead < 0) {
                perror("dec_server: ERROR reading auth");
                exit(1);
            }
            // Trim trailing newline or carriage return
            for (ssize_t i = 0; i < authRead; i++) {
                if (clientAuth[i] == '\n' || clientAuth[i] == '\r') {
                    clientAuth[i] = '\0';
                    break;
                }
            }

            if (strcmp(clientAuth, "dec_bs") != 0) {
                char response[] = "invalid";
                write(newsockfd, response, strlen(response));
                exit(2);
            } else {
                char response[] = "dec_d_bs";
                write(newsockfd, response, strlen(response));
            }

            // --- Read ciphertext and key until two newlines are found ---
            char *keyStart = NULL;
            int bytes_remaining = sizeof(buffer);
            char *p = buffer;
            int newlines = 0;
            ssize_t bytesRead;

            while ((bytesRead = read(newsockfd, p, bytes_remaining)) > 0) {
                for (ssize_t i = 0; i < bytesRead; i++) {
                    if (p[i] == '\n') {
                        newlines++;
                        if (newlines == 1) {
                            keyStart = p + i + 1;
                        }
                    }
                }
                if (newlines == 2) break;
                p += bytesRead;
                bytes_remaining -= bytesRead;
                if (bytes_remaining <= 0) {
                    fprintf(stderr, "dec_server: ERROR buffer overflow\n");
                    exit(1);
                }
            }
            if (bytesRead < 0) {
                perror("dec_server: ERROR reading from socket");
                exit(1);
            }

            // Separate ciphertext and key strings
            char message[BUFFER_SIZE], key[BUFFER_SIZE];
            memset(message, 0, sizeof(message));
            memset(key, 0, sizeof(key));

            if (keyStart == NULL) {
                fprintf(stderr, "dec_server: ERROR input missing key\n");
                exit(1);
            }

            int msgLen = (int)(keyStart - buffer - 1); // exclude newline before key
            if (msgLen < 0) {
                fprintf(stderr, "dec_server: ERROR parsing input\n");
                exit(1);
            }

            strncpy(message, buffer, msgLen);
            message[msgLen] = '\0'; // null terminate message
            strcpy(key, keyStart);

            int keyLen = strlen(key);
            // Remove trailing newline from key if present
            if (keyLen > 0 && key[keyLen - 1] == '\n') {
                key[keyLen - 1] = '\0';
                keyLen--;
            }

            // Validate ciphertext chars
            for (int i = 0; i < msgLen; i++) {
                if (!isValidChar(message[i])) {
                    fprintf(stderr, "dec_server: ERROR invalid char in ciphertext\n");
                    exit(1);
                }
            }
            // Validate key chars
            for (int i = 0; i < keyLen; i++) {
                if (!isValidChar(key[i])) {
                    fprintf(stderr, "dec_server: ERROR invalid char in key\n");
                    exit(1);
                }
            }

            // Check key length
            if (keyLen < msgLen) {
                fprintf(stderr, "dec_server: ERROR key shorter than ciphertext\n");
                exit(1);
            }

            // Perform decryption
            decrypt(message, key);

            // Write decrypted message back to client (no trailing nulls)
            ssize_t written = write(newsockfd, message, strlen(message));
            if (written < 0) {
                perror("dec_server: ERROR writing to socket");
                exit(1);
            }

            close(newsockfd);
            exit(0);
        } else {
            // Parent process
            activeConnections++;
            // Reap any finished child processes to reduce activeConnections
            while (waitpid(-1, NULL, WNOHANG) > 0) {
                activeConnections--;
            }
            close(newsockfd);
        }
    }

    close(sockfd);
    return 0;
}
