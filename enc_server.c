#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>

#define BUFFER_SIZE 1024

// Helper function to print error message and then exit the program
void error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Converts a character into an integer value between 0 and 26
int charToInt(char c) {
    if (c == ' ') {
        return 26;
    } else if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    } else {
        return 0; 
    }
}

// Converts an integer in the range 0-26 back to character 
char intToChar(int val) {
    if (val == 26) {
        return ' ';
    } else {
        return val + 'A';
    }
}

// Encryption function
void encrypt(char* message, char* key, int length) {
    for (int i = 0; i < length; i++) {
        int sum = charToInt(message[i]) + charToInt(key[i]);
        message[i] = intToChar(sum % 27);
    }
    message[length] = '\0'; // Null terminate after encryption
}

// SIGCHLD handler to reap zombie children immediately
void reap_zombie(int sig) {
    (void)sig; // suppress unused parameter warning
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Trim newline and whitespace from end of string (in place)
void trim_newline(char *str) {
    int len = strlen(str);
    while (len > 0 && (str[len-1] == '\n' || str[len-1] == '\r' || isspace(str[len-1]))) {
        str[len-1] = '\0';
        len--;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(1);
    }

    // Set up SIGCHLD handler to avoid zombies
    struct sigaction sa;
    sa.sa_handler = reap_zombie;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        error("sigaction");
    }

    int listenSocketFD, establishedConnectionFD;
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t clientLen;
    int portNumber = atoi(argv[1]);

    // Set up server address struct
    memset(&serverAddress, 0, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(portNumber);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Create socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocketFD < 0) error("ERROR opening socket");

    // Bind socket to port
    if (bind(listenSocketFD, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0)
        error("ERROR on binding");

    // Listen for connections
    listen(listenSocketFD, 5);

    while (1) {
        clientLen = sizeof(clientAddress);
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *) &clientAddress, &clientLen);
        if (establishedConnectionFD < 0) error("ERROR on accept");

        pid_t pid = fork();
        if (pid < 0) {
            error("ERROR on fork");
        } 
        else if (pid == 0) {
            // Child process handles the client
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, BUFFER_SIZE);

            // Step 1: Read client identification string ("otp_enc")
            int n = recv(establishedConnectionFD, buffer, BUFFER_SIZE - 1, 0);
            if (n < 0) {
                close(establishedConnectionFD);
                error("ERROR reading from socket");
            }
            buffer[n] = '\0';
            trim_newline(buffer);

            if (strcmp(buffer, "otp_enc") != 0) {
                send(establishedConnectionFD, "no", 2, 0);
                close(establishedConnectionFD);
                exit(2);
            } else {
                send(establishedConnectionFD, "yes", 3, 0);
            }

            // Step 2: Receive message length as string
            memset(buffer, 0, BUFFER_SIZE);
            n = recv(establishedConnectionFD, buffer, BUFFER_SIZE - 1, 0);
            if (n < 0) {
                close(establishedConnectionFD);
                error("ERROR reading from socket");
            }
            buffer[n] = '\0';
            trim_newline(buffer);
            int messageLength = atoi(buffer);
            if (messageLength <= 0) {
                close(establishedConnectionFD);
                exit(1);
            }

            // Confirm ready to receive
            send(establishedConnectionFD, "cont", 4, 0);

            // Step 3: Receive message data fully
            char *message = malloc(messageLength + 1);
            if (!message) {
                close(establishedConnectionFD);
                error("Memory allocation failed");
            }
            int totalReceived = 0;
            while (totalReceived < messageLength) {
                memset(buffer, 0, BUFFER_SIZE);
                n = recv(establishedConnectionFD, buffer, BUFFER_SIZE, 0);
                if (n <= 0) {
                    free(message);
                    close(establishedConnectionFD);
                    error("ERROR reading from socket");
                }
                int toCopy = n;
                if (totalReceived + toCopy > messageLength) {
                    toCopy = messageLength - totalReceived;
                }
                memcpy(message + totalReceived, buffer, toCopy);
                totalReceived += toCopy;
            }
            message[messageLength] = '\0';

            // Step 4: Receive key data fully (same length as message)
            char *key = malloc(messageLength + 1);
            if (!key) {
                free(message);
                close(establishedConnectionFD);
                error("Memory allocation failed");
            }
            totalReceived = 0;
            while (totalReceived < messageLength) {
                memset(buffer, 0, BUFFER_SIZE);
                n = recv(establishedConnectionFD, buffer, BUFFER_SIZE, 0);
                if (n <= 0) {
                    free(message);
                    free(key);
                    close(establishedConnectionFD);
                    error("ERROR reading from socket");
                }
                int toCopy = n;
                if (totalReceived + toCopy > messageLength) {
                    toCopy = messageLength - totalReceived;
                }
                memcpy(key + totalReceived, buffer, toCopy);
                totalReceived += toCopy;
            }
            key[messageLength] = '\0';

            // Step 5: Encrypt message
            encrypt(message, key, messageLength);

            // Step 6: Send encrypted message back to client in chunks
            int totalSent = 0;
            while (totalSent < messageLength) {
                int toSend = (messageLength - totalSent) > BUFFER_SIZE ? BUFFER_SIZE : (messageLength - totalSent);
                n = send(establishedConnectionFD, message + totalSent, toSend, 0);
                if (n < 0) {
                    free(message);
                    free(key);
                    close(establishedConnectionFD);
                    error("ERROR writing to socket");
                }
                totalSent += n;
            }

            // Clean up
            free(message);
            free(key);
            close(establishedConnectionFD);
            exit(0); // Child terminates after serving client
        } else {
            // Parent process closes connection (child handles communication)
            close(establishedConnectionFD);
            // Reaping children handled by SIGCHLD handler
        }
    }

    close(listenSocketFD);
    return 0;
}
