#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <signal.h>

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

void encrypt(char *message, const char *key) {
    // Loops to end of the message
    // Stops if it reaches a newline character
    // Stops if it reaches null terminators
    for (int i = 0; message[i] != '\n' && message[i] != '\0'; i++) {
        // Converts the characters of the messages and the key into integers
        int mVal = charToInt(message[i]);
        int kVal = charToInt(key[i]);
        // Adds the message value and the key value and takes the result modulo 27 to wrap around if it exceeds 26
        int sum = (mVal + kVal) % 27;
        // Converts the integer result back into a character 
        message[i] = intToChar(sum);
    }
}

// Integer file descriptor (connectionFD) representing the socket connected to a client
void handleClient(int connectionFD) {
    char buffer[BUFFER_SIZE];       // Used for reading data from the socket
    char message[MAX_MESSAGE_SIZE]; // Used to store the full message sent by the client
    char key[MAX_MESSAGE_SIZE];     // Used to store the key sent by the client

    // Set both message and key arrays and setting all bytes to 0
    memset(message, 0, MAX_MESSAGE_SIZE);
    memset(key, 0, MAX_MESSAGE_SIZE);

    // Verify that the connection to enc_server is coming from enc_client
    memset(buffer, 0, BUFFER_SIZE); // Set buffer bytes to 0
    // Receives data from client via the socket connectionFD
    int charsRead = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "ERROR reading from socket\n");
        close(connectionFD);
        exit(1);
    }

    // Compares the received string in buffer with otp_enc
    // Verify the client 
    if (strcmp(buffer, "otp_enc") != 0) {
        send(connectionFD, "no", 2, 0);
        close(connectionFD);
        exit(2);
    }

    send(connectionFD, "yes", 3, 0);

    // Child receives plaintext from enc_client via the connected socket
    memset(buffer, 0, BUFFER_SIZE); // Set buffer bytes to 0
    // Receive a string representing the length of message that the client will send
    charsRead = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
    if (charsRead < 0) {
        fprintf(stderr, "ERROR reading from socket\n");
        close(connectionFD);
        exit(1);
    }
    // Converts the string received in buffer to an integer (length)
    int size = atoi(buffer);
    // Tells the client the server is ready to receive the message data
    send(connectionFD, "cont", 4, 0); 

    int totalReceived = 0;
    // Loops to receive data until the entire message has been received
    while (totalReceived < size) {
        memset(buffer, 0, BUFFER_SIZE);
        int received = recv(connectionFD, buffer, BUFFER_SIZE - 1, 0);
        // Checks if the recv called failed 
        if (received < 0) {
            fprintf(stderr, "ERROR reading from socket\n");
            close(connectionFD);
            exit(1);
        }
        // Copies bytes received 
        memcpy(message + totalReceived, buffer, received);
        totalReceived += received;
    }

    // Key passed in must be at least as big as the plaintext
    totalReceived = 0;
    // Loop continues receving data until the full is received
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

    // Encrypt the received message using the received key
    // message is the plaintext message received from the client
    // key (same length as the message) 
    encrypt(message, key);

    // Initialize counter to keep track of how many bytes have been sent 
    int totalSent = 0;
    while (totalSent < size) {
        int sent = send(connectionFD, message + totalSent, size - totalSent, 0);
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
    int listenSocketFD, connectionFD, portNumber;   //listenSocketFD is file descriptor for listening socket waiting for client connections
    socklen_t clientSize;   // Hold the size of the clientAddress structured, used when accepting connections
    struct sockaddr_in serverAddress, clientAddress;
    int activeChildren = 0;  // Track number of active children

    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    memset(&serverAddress, 0, sizeof(serverAddress));
    // Converts the first command line argument to an integer
    // The integer is the port number the server will listen on
    portNumber = atoi(argv[1]);
    // Sets the address family to IPv4
    serverAddress.sin_family = AF_INET;
    // Sets the port number for the socket
    // htons converts the port number from host byte order to network byte order (big-endian)
    serverAddress.sin_port = htons(portNumber);
    // Sets the IP address for the socket ot listen on 
    // INADDR_ANY means the server will accept connections on any ofthe host's network interfaces
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    // Creates a new socket
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocketFD < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    // Associates listenSocketFD with the server address and port
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0) {
        perror("ERROR on binding");
        close(listenSocketFD);
        exit(1);    // Without binding, the server cannot listen on the chosen port
    }

    listen(listenSocketFD, 5);  // 5 specifies the maximum length of the queue for pending connections

    // The server will run indefinitely until manually stopped
    while (1) {
        // Checks for any terminated child processes
        while (activeChildren > 0) {
            pid_t pid = waitpid(-1, NULL, WNOHANG);
            if (pid <= 0) {
                break; 
            }
            activeChildren = activeChildren -1;
        }

        // Prevents the server from spawning more than MAX_CHILDREN (5)
        if (activeChildren >= MAX_CHILDREN) {
            pid_t pid = wait(NULL); 
            if (pid > 0) {
                activeChildren = activeChildren -1;
            }
        }

        // accept() waits for a client connection request
        clientSize = sizeof(clientAddress);
        connectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &clientSize);
        if (connectionFD < 0) {
            fprintf(stderr, "ERROR on accept\n");
            continue;
        }

        // The server forks a new process to handle the client connection 
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "ERROR on fork\n");
            close(connectionFD);
            continue;
        }

        // Child process
        if (pid == 0) {
            close(listenSocketFD);
            handleClient(connectionFD);
            exit(0);
        } else {
            // Parent process
            close(connectionFD);
            activeChildren++;  // Increment count of active children
        }
    }

    close(listenSocketFD);
    return 0;
}
