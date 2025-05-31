#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <ctype.h>

#define MAX_MESSAGE_SIZE 100000
#define BUFFER_SIZE 1024 

// Helper function to print an error message and exit the program with failure
void reportError(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

// Returns the number of valid characters in the file
int countValidChars(const char* filepath) {
    FILE* file = fopen(filepath, "r");
    if (!file) reportError("Error opening file");
    // Track valid characters
    int count = 0, c;
    // EOF end of file or newline character
    while ((c = fgetc(file)) != EOF && c != '\n') {
        // If character is not an uppercase letter and not a space then invalid
        if (!isupper(c) && c != ' ') reportError("Invalid characters in file");
        count++;
    }

    fclose(file);
    return count;
}

// Sends the contents of a file over a socket
void sendFileContent(int socketFD, const char* filepath, int length) {
    char buffer[BUFFER_SIZE];
    int totalSent = 0, bytesRead, bytesSent;
    int fd = open(filepath, O_RDONLY);

    if (fd < 0) reportError("Error opening file for sending");

    while (totalSent < length) {
        memset(buffer, '\0', BUFFER_SIZE);
        bytesRead = read(fd, buffer, BUFFER_SIZE - 1);
        if (bytesRead <= 0) break;

        // Sends the bytes read from the file over the socket specified 
        bytesSent = send(socketFD, buffer, bytesRead, 0);
        if (bytesSent < 0) reportError("Error sending file data");
        // Adds the number of bytes successfully sent in this iteration
        totalSent += bytesSent;
    }

    close(fd);
}

int main(int argc, char* argv[]) {
    int socketFD, portNum, charsWritten, charsRead;
    struct sockaddr_in serverAddr;
    struct hostent* serverHost;
    char buffer[BUFFER_SIZE];
    char result[MAX_MESSAGE_SIZE] = "";

    // If the number of command-line argument is exactly 4, program name and 3 arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    int textLen = countValidChars(argv[1]);
    int keyLen = countValidChars(argv[2]);
    if (keyLen < textLen) reportError("Key is too short");

    memset(&serverAddr, '\0', sizeof(serverAddr));
    portNum = atoi(argv[3]);
    // Specify teh address family as IPv4
    serverAddr.sin_family = AF_INET;
    // Convert the port number to network byte order (big-endian )
    serverAddr.sin_port = htons(portNum);
    serverHost = gethostbyname("localhost");
    if (!serverHost) reportError("No such host");
    memcpy(&serverAddr.sin_addr.s_addr, serverHost->h_addr, serverHost->h_length);

    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) reportError("Error opening socket");

    // Attempts to connect the socket to the server address and port specified
    if (connect(socketFD, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portNum);
        exit(2);
    }

    // Handshake
    // Sends a handshake string "ENC_CLIENT" to teh server to identify the client
    send(socketFD, "ENC_CLIENT", strlen("ENC_CLIENT"), 0);
    memset(buffer, '\0', BUFFER_SIZE);
    recv(socketFD, buffer, BUFFER_SIZE - 1, 0);
    if (strcmp(buffer, "ENC_SERVER") != 0) {
        fprintf(stderr, "Connection rejected by server on port %d\n", portNum);
        exit(2);
    }

    // Send length 
    sprintf(buffer, "%d", textLen);
    // Sends length of the plaintext file to the server to show how much data to expect
    send(socketFD, buffer, strlen(buffer), 0);
    recv(socketFD, buffer, BUFFER_SIZE - 1, 0);  

    // Send plaintext over the socket
    // textLen makes sure we only send valid characters
    sendFileContent(socketFD, argv[1], textLen);
    // Send key
    sendFileContent(socketFD, argv[2], textLen);

    // Get ciphertext from the server
    int totalReceived = 0;
    // Continuously receive chunks of data from the server
    while (totalReceived < textLen) {
        memset(buffer, '\0', BUFFER_SIZE);
        charsRead = recv(socketFD, buffer, BUFFER_SIZE - 1, 0);
        if (charsRead < 0) reportError("Error receiving ciphertext");
        totalReceived += charsRead;
        strcat(result, buffer);
    }

    printf("%s\n", result);
    close(socketFD);
    return 0;
}