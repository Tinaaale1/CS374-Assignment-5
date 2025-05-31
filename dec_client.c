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
    while ((c = fgetc(file)) != EOF && c != '\n') {
        if (!isupper(c) && c != ' ') reportError("Invalid characters in file");
        count++;
    }
    fclose(file);
    return count;
}

// Sends the contents of a file over a socket
void sendFileContent(int socketFD, const char* filepath, int length) {
    char buffer[BUFFER_SIZE];
    // Tracks how much bytes have been sent
    // bytesRead is how many bytes were read from the file in one chunk
    // bytesSent is how many bytes were sent over the socket in one chunk
    int totalSent = 0, bytesRead, bytesSent;
    int fd = open(filepath, O_RDONLY);

    if (fd < 0) reportError("Error opening file for sending");

    while (totalSent < length) {
        memset(buffer, '\0', BUFFER_SIZE);
        bytesRead = read(fd, buffer, BUFFER_SIZE - 1);
        if (bytesRead <= 0) break;

        bytesSent = send(socketFD, buffer, bytesRead, 0);
        if (bytesSent < 0) reportError("Error sending file data");
        totalSent += bytesSent;
    }

    close(fd);
}

int main(int argc, char* argv[]) {
    int socketFD, portNum, charsRead;
    // Stores server address information from the connection
    struct sockaddr_in serverAddr;
    struct hostent* serverHost;
    char buffer[BUFFER_SIZE];   // Temporary buffer for reading and sending data
    char result[MAX_MESSAGE_SIZE] = ""; 
    // If not exactly 4, including the program name 
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ciphertext key port\n", argv[0]);
        exit(1);
    }

    int textLen = countValidChars(argv[1]); // textLen is the number of valid characters in ciphertext
    int keyLen = countValidChars(argv[2]);  // keyLen is the number of valid characters in key
    if (keyLen < textLen) reportError("Key is too short");  // Checks if the key is at least as long as the ciphertext

    memset(&serverAddr, '\0', sizeof(serverAddr));
    // Converts the port number to integer
    portNum = atoi(argv[3]);
    // Specifies that the address is for an IPv4 network 
    serverAddr.sin_family = AF_INET;
    // Converts teh port number to network byte order using htons()
    serverAddr.sin_port = htons(portNum);
    serverHost = gethostbyname("localhost");
    if (!serverHost) reportError("No such host");
    memcpy(&serverAddr.sin_addr.s_addr, serverHost->h_addr, serverHost->h_length);

    socketFD = socket(AF_INET, SOCK_STREAM, 0);
    // If socket creation failed, terminate the program
    if (socketFD < 0) reportError("Error opening socket");
    // Connect to the server using the socket 
    // If the connection fails, print an error and exits
    if (connect(socketFD, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        fprintf(stderr, "Error: could not contact dec_server on port %d\n", portNum);
        exit(2);
    }

    // Handshake
    // Sends handshake message to the server
    // otp_dec identifies teh client as the decryption client 
    send(socketFD, "otp_dec", strlen("otp_dec"), 0);
    memset(buffer, '\0', BUFFER_SIZE);
    // Receives the server's response to the handshake 
    recv(socketFD, buffer, BUFFER_SIZE - 1, 0);

    // Server should respond with "yes" for dec_server, reject otherwise
    if (strcmp(buffer, "yes") != 0) {
        fprintf(stderr, "Connection rejected by server on port %d\n", portNum);
        exit(2);
    }

    // Converts the integer textLen, the length of the ciphertext, into a string and stores it in buffer
    sprintf(buffer, "%d", textLen);
    // Tells server how many characters of ciphertext to expect
    send(socketFD, buffer, strlen(buffer), 0);
    memset(buffer, '\0', BUFFER_SIZE);
    recv(socketFD, buffer, BUFFER_SIZE - 1, 0);
    // Continue, the server is reasdy to receive teh ciphertext and key
    // If not cont then the server is not following the expected protocol
    if (strcmp(buffer, "cont") != 0) {
        fprintf(stderr, "Server protocol error\n");
        exit(2);
    }

    // Send ciphertext and key
    sendFileContent(socketFD, argv[1], textLen);
    sendFileContent(socketFD, argv[2], textLen);

    // Counter to keep track of the total number of bytes received from the server
    int totalReceived = 0;
    while (totalReceived < textLen) {
        memset(buffer, '\0', BUFFER_SIZE);
        charsRead = recv(socketFD, buffer, BUFFER_SIZE - 1, 0);
        if (charsRead < 0) reportError("Error receiving plaintext");
        totalReceived += charsRead;
        strncat(result, buffer, charsRead);
    }

    printf("%s\n", result);
    close(socketFD);
    return 0;
}
