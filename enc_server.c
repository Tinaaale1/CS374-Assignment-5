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
    int value = c - 'A';
    if (c == ' ') {
        value = 26;
    }
    return value;
}

// Converts an integer back to its corresponding character
char intToChar(int i) {
    char c;
    if (i == 26) {
        c = ' ';
    } else {
        c = i + 'A';
    }
    return c;
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

void encrypt(char message[], char key[]) {
    int i;
    // Loop through message until reach newline
    for (i = 0; message[i] != '\n'; i++) {
        // Convert message character to integer
        int mVal = charToInt(message[i]);   
        // Convert key character to integer
        int kVal = charToInt(key[i]);
        // Add and modulo 27 and then convert back to character
        message[i] = intToChar((mVal + kVal) % 27);
    }
    // Replace newline with string terminator
    message[i] = '\0';  
}

int main(int argc, char *argv[]) {
    int sockfd, newsockfd, portnum, optval;
    // sockfd is the file descriptor for the server
    // newsockfd is the socket for accepted client connections 
    // portnum is the port number to listen on 
    // optval is to hold the value of a socket option to set 
    socklen_t clientlen;
    struct sockaddr_in server_addr, client_addr;
    // Checks if the user provided one argument, the port
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("enc_server: ERROR opening socket");
    // Set socket option to 1 to allow resuse of port 
    optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));

    memset(&server_addr, 0, sizeof(server_addr));
    // Converts port number from string to integer
    portnum = atoi(argv[1]);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    // Converted to network byte order by htons
    server_addr.sin_port = htons(portnum);
    // Associates the socket with the address and port specified 
    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error("enc_server: ERROR on binding");
    // Allows up 5 queued connections waiting 
    listen(sockfd, MAX_CONNECTIONS);
    // Initialize counter to keep track of connected clients 
    int activeConnections = 0;
    // Loop to accept new client connections 
    while (1) {
        // Size of the client address structure
        clientlen = sizeof(client_addr);
        // Waits for a client connection
        // Returns a new socket file descriptor 
        newsockfd = accept(sockfd, (struct sockaddr*)&client_addr, &clientlen);
        
        // If failed print error and continue to loop 
        if (newsockfd < 0) {
            fprintf(stderr, "enc_server: ERROR on accept\n");
            continue;
        }

        // If server has 5 active client, wait until a child process finishes to accept more
        while (activeConnections >= MAX_CONNECTIONS) {
            pause();  // Wait for child to finish
        }
        // Create a new process to handle the client connection separately
        pid_t pid = fork();
        // If failed print error and close the client socket and continue accepting other connections
        if (pid < 0) {
            fprintf(stderr, "enc_server: ERROR forking\n");
            close(newsockfd);
            continue;
        }

        if (pid == 0) {
            // Child process closees the listening socket 
            close(sockfd);
            char buffer[BUFFER_SIZE];
            memset(buffer, 0, sizeof(buffer));
            // Where the key starts in the buffer
            char *keyStart;
            // Keeps track of how much space is left in the buffer
            int bytes_remaining = sizeof(buffer);
            char *p = buffer;
            int newlines = 0;

            // Store client authentication string
            char clientAuth[32];
            memset(clientAuth, 0, sizeof(clientAuth));
            // Read the authentication string sent by the client
            read(newsockfd, clientAuth, sizeof(clientAuth) - 1);
            // Check if the client is enc_client 
            if (strcmp(clientAuth, "enc_bs") != 0) {
                char response[] = "invalid";
                write(newsockfd, response, sizeof(response));
                // Exit child process on failed authentication
                exit(2);
            } else {
                char response[] = "enc_d_bs";
                write(newsockfd, response, sizeof(response));
            }

            // Store how many bytes read from the socket 
            int bytesRead;
            // Loop continues up bytes_remaining 
            while ((bytesRead = read(newsockfd, p, bytes_remaining)) > 0) {
                for (int i = 0; i < bytesRead; i++) {
                    if (p[i] == '\n') {
                        newlines++;
                        if (newlines == 1) keyStart = p + i + 1;
                    }
                }
                if (newlines == 2) break;
                // Advances the pointer forward by the number of bytes
                p += bytesRead;
                // Decreases the remaining space in the buffer
                bytes_remaining -= bytesRead;
            }
            // If negative value then an error occurred reading from the socket
            if (bytesRead < 0) {
                fprintf(stderr, "enc_server: ERROR reading from socket\n");
                exit(1);
            }

            // Separate message and key
            char message[BUFFER_SIZE], key[BUFFER_SIZE];
            memset(message, 0, sizeof(message));
            memset(key, 0, sizeof(key));
            // keyStart is a pointer to the start key 
            // buffer is the start of the received data containing both message and key 
            //1 to exclude the nwline character before the key
            int msgLen = keyStart - buffer - 1;
            strncpy(message, buffer, msgLen);
            strcpy(key, keyStart);

            // Calculates the length of the key string
            int keyLen = strlen(key);
            // If the last character of the key is a newline, -1 
            if (key[keyLen - 1] == '\n') keyLen--;
            // If the key is shorter than the plaintext message then print error message
            if (keyLen < msgLen) {
                fprintf(stderr, "enc_server: ERROR - key shorter than message\n");
                exit(1);
            }

            // Loop over each character in the message
            for (int i = 0; i < msgLen; i++) {
                if (!isValidChar(message[i])) {
                    fprintf(stderr, "enc_server: ERROR - invalid character in message\n");
                    exit(1);
                }
            }
            // Loop over every character in the key
            for (int i = 0; i < keyLen; i++) {
                if (!isValidChar(key[i])) {
                    fprintf(stderr, "enc_server: ERROR - invalid character in key\n");
                    _Exit(1);
                }
            }
            // Modifies the message in place converting it into ciphertext using the key
            // One-time pad
            encrypt(message, key);
            write(newsockfd, message, strlen(message));
            close(newsockfd);
            exit(0);
        } else {
            // Runs in the parent process after forking
            activeConnections += 1;
            // Finished child processes
            while (waitpid(-1, NULL, WNOHANG) > 0)
                activeConnections -= 1;
            close(newsockfd);
        }
    }

    close(sockfd);
    return 0;
}