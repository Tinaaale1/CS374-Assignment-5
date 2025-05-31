#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAX_MESSAGE_SIZE 100000
#define BUFFER_SIZE 1024
#define MAX_CHILDREN 5  // Limits how many simultaneous connections the server accepts/forks at a time 

// Helper function to print error message and then exit the program
void error(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// Converts a character into an integer value between 0 and 26
int charToInt(char c) {
    if (c == ' ') return 26;
    else return c - 'A';
}

// Converts an integer in the range 0-26 back to character 
char intToChar(int i) {
    if (i == 26) return ' ';
    else return i + 'A';
}

// Modifies the ciphertext in place to turn it into plaintext 
// ciphertext containing the encrypted message
// key used to decrypt the message
void decrypt(char *ciphertext, const char *key) {
    // Iterates through each character until a newline or null terminator
    for (int i = 0; ciphertext[i] != '\n' && ciphertext[i] != '\0'; i++) {
        // Converts each character from the ciphertext into a number
        int cVal = charToInt(ciphertext[i]);
        int kVal = charToInt(key[i]);
        int dVal = (cVal - kVal + 27) % 27;  // Add 27 to avoid negative results
        ciphertext[i] = intToChar(dVal;
    }
}

// Handle client connection
void handleClient(int connectionFD) {
    char buffer[BUFFER_SIZE];       // Used for reading data from the socket
    char message[MAX_MESSAGE_SIZE]; // Used to store the full ciphertext sent by the client
    char key[MAX_MESSAGE_SIZE];     // Used to store the key sent by the client

    memset(message, 0, MAX_MESSAGE_SIZE);
    memset(key, 0, MAX_MESSAGE_SIZE);

    // Verify that the connection to dec_server is coming from dec_client
    memset(buffer, 0, BUFFER_SIZE);
    // Waits for data from the client on the socket
    int charsRead = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "ERROR reading from socket\n");
        close(connectionFD);
        exit(1);
    }

    // Checks if the client is allowed to use the server 
    if (strcmp(buffer, "otp_dec") != 0) {
        // Compares the string received in buffer to the expected handshake string 
        // If does not match, the client is invlaid or not allowed
        send(connectionFD, "no", 2, 0);
        close(connectionFD);
        exit(2);
    }
    // If handshake is successful then send yes back to client 
    // Proceed sending ciphertext and key
    send(connectionFD, "yes", 3, 0);

    // Reads data sent by the client over the socket into the buffer
    memset(buffer, 0, BUFFER_SIZE);
    charsRead = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "ERROR reading from socket\n");
        close(connectionFD);
        exit(1);
    }
    int size = atoi(buffer);

    // Tell client to continue sending ciphertext
    send(connectionFD, "cont", 4, 0);

    // Keeps track of the total number of bytes
    int totalReceived = 0;
    // Continue receving until the full ciphertext
    while (totalReceived < size) {
        memset(buffer, 0, BUFFER_SIZE);
        int received = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
        if (received < 0) {
            fprintf(stderr, "ERROR reading from socket\n");
            close(connectionFD);
            exit(1);
        }
        memcpy(message + totalReceived, buffer, received);
        totalReceived += received;
    }

    // Receive key same length as the ciphertext over the socket 
    totalReceived = 0;
    // Loops continues until the full key has been received
    while (totalReceived < size) {
        memset(buffer, 0, BUFFER_SIZE);
        int received = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
        if (received < 0) {
            fprintf(stderr, "ERROR reading from socket\n");
            close(connectionFD);
            exit(1);
        }
        memcpy(key + totalReceived, buffer, received);
        totalReceived += received;
    }

    // Decrypt the received ciphertext using the provided key
    decrypt(message, key);

    // Send the decrypted plaintext back to client
    int totalSent = 0;
    while (totalSent < size) {
        int sent = send(connectionFD, message + totalSent, size - totalSent, 0);
        // If the write fails then print error
        if (sent < 0) {
            fprintf(stderr, "ERROR writing to socket\n");
            close(connectionFD);
            exit(1);
        }
        totalSent += sent;
    }

    close(connectionFD);
}

int main(int argc, char *argv[]) {
    int listenSocketFD, connectionFD, portNumber;
    socklen_t clientSize;
    struct sockaddr_in serverAddress, clientAddress;
    int activeChildren = 0;

    // Checks if teh user provided the required command-line argument
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    // Initializes the entire serverAddress structure to 0
    memset(&serverAddress, 0, sizeof(serverAddress));
    // Converts the port number to an integer
    // The server will listen on this port
    portNumber = atoi(argv[1]);
    // Sets the address family to IPv4
    serverAddress.sin_family = AF_INET;
    // Sets the port number for the server 
    serverAddress.sin_port = htons(portNumber);
    // Sets the IP address for the server socket
    serverAddress.sin_addr.s_addr = INADDR_ANY;
    // Creates a new socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    // Checks if socket creation failed 
    if (listenSocketFD < 0) {
        perror("ERROR opening socket");
        exit(1);
    }
    // Binds the socket to the IP address and port specified in serverAddress
    // Associates the socket with the local address
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("ERROR on binding");
        close(listenSocketFD);
        exit(1);
    }

    listen(listenSocketFD, 5);

    // Infinite loop that keeps the server running to accept and handle multiple clients
    while (1) {
        // Checks for any finished child prcesses without blocking
        while (activeChildren > 0) {
            pid_t pid = waitpid(-1, NULL, WNOHANG);
            if (pid <= 0) {
                break;
            }
            activeChildren -= 1;
        }
        // If the number of active child processes exceeds MAX_CHILDREN
        if (activeChildren >= MAX_CHILDREN) {
            pid_t pid = wait(NULL);
            if (pid > 0) {
                activeChildren -=1;
            }
        }
        // Initliaze clientSize to the size of the clientAddress before calling accept()
        // accept() waits for an incoming client connection
        clientSize = sizeof(clientAddress);
        connectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &clientSize);
        if (connectionFD < 0) {
            fprintf(stderr, "ERROR on accept\n");
            continue;
        }
        // Creates a new child process
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "ERROR on fork\n");
            close(connectionFD);
            continue;
        }
        // Close the listening socket since child does not accept new clients
        if (pid == 0) {
            close(listenSocketFD);
            handleClient(connectionFD);
            exit(0);
        } else {
            // Close the listening socket because chld does not accept new clients
            close(connectionFD);
            activeChildren++;
        }
    }

    close(listenSocketFD);
    return 0;
}