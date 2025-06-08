#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1000

// From server.c
// Print formatted error message and exit with status code 
void error(int exitCode, const char *message) {
    fprintf(stderr, "Client error: %s\n", message);
    exit(exitCode);
}

// From server.c 
// Set up the address struct 
void setupAddressStruct(struct sockaddr_in* address, int portNumber){
    // Clear out the address struct 
    memset((char*) address, '\0', sizeof(*address));
    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);
    // Allow a client at any address to connect to this server 
    address->sin_addr.s_addr = INADDR_ANY;
}

// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397
void sendData(int connectionSocket, char* data) {
    // Calculate the number of characters 
    int len = (int)strlen(data);
    // Sends the length of the data  
    int charsWritten = send(connectionSocket, &len, sizeof(len), 0);
    // If negative, error occurred 
    if (charsWritten < 0) {
        error(1, "CLIENT: ERROR writing to socket");
    }
    // Track how many bytes already sent
    int totalSent = 0;
    // Loop until the total number of bytes sent is equal to the length 
    while (totalSent < len) {
        // Determine how many bytes to send
        int bytesToSend;
            if (len - totalSent < BUFFER_SIZE) {
                bytesToSend = len - totalSent;
            } else {
                bytesToSend = BUFFER_SIZE;
            }
        // Send message through the socket
        charsWritten = send(connectionSocket, data + totalSent, bytesToSend, 0);
        if (charsWritten < 0) {
            error(1, "CLIENT: WARNING: Not all data written to socket!");
        }
        // Updates how many bytes were successfully sent
        totalSent += charsWritten;
    }
}

// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397
char* receive(int connectionSocket) {
    int len;
    // Calls recv() to read data from the socket
    // If negative value then error occurred
    if (recv(connectionSocket, &len, sizeof(len), 0) < 0)
        error(1, "CLIENT: ERROR reading from socket");
    // Allocate memory to store incoming messsage
    char* result = malloc(len + 1);
    if (!result)
        error(1, "Unable to allocate memory");
    int charsRead;
    // Loop to read data for entire message
    for (int i = 0; i < len; i += charsRead) {
        int totalRead;
        if (len - i > BUFFER_SIZE - 1) {
            totalRead = BUFFER_SIZE - 1;
        } else {
            totalRead = len - i;
        }
        charsRead = (int)recv(connectionSocket, result + i, totalRead, 0);
        if (charsRead < 0)
            error(1, "ERROR reading from socket");
    }
    result[len] = '\0';
    return result;
}

// Verify the client 
void verifyClient(int connectionSocket) {
    char client[4], server[4] = "enc";
    memset(client, '\0', sizeof(client));
    // Receives a message up to 4 bytes from the client through the socket
    if (recv(connectionSocket, client, sizeof(client), 0) < 0)
        error(1, "ERROR reading from socket");
    // Sends back to client 
    // Handshake message to verify client
    if (send(connectionSocket, server, sizeof(server), 0) < 0)
        error(1, "ERROR writing to socket");
    // Compares the received client string to the expected "enc" string 
    if (strcmp(client, server)) {
        // If strings do not match, close socket
        close(connectionSocket);
        error(2, "Rejected connection: Client not validated");
    }
}

void otpEncryption(int connectionSocket) {
    // Read a plaintext message from the client
    char* plaintext = receive(connectionSocket);
    char* key = receive(connectionSocket);
    // Calculates the length of the plaintext message
    // Key is the same length  
    int len = (int)strlen(plaintext);
    char* result = (char*) malloc(len + 1);

    for (int i = 0; i < len; i++) {
        // Converts the text into a number between 0 and 26
        int text;
        if (plaintext[i] == ' ') {
            text = 26;
        } else {
            text = plaintext[i] - 'A';
        }
        // Converts the character into a number between 0 and 26
        int keyVal;
        if (key[i] == ' ') {
            keyVal = 26;
        } else {
            keyVal = key[i] - 'A';
        }
        // Wrap around if the result is over 26
        int encryptVal = (text + keyVal) % 27;
        // If 26 then result is a space
        if (encryptVal == 26) {
            result[i] = ' ';
        } else {
            result[i] = encryptVal + 'A';
        }
    }
    // Adds a null terminator to the end of the encrypted string
    result[len] = '\0';
    // Sends the encrypted message back to the client
    sendData(connectionSocket, result);
    free(result);
    free(plaintext);
    free(key);
    close(connectionSocket);
}

// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397 
int main(int argc, const char * argv[]) {
    // Checks if the user provided a port number 
    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }
    // Create a socket
    int listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocket < 0)
        error(1, "Error opening socket");
    // From server.c
    struct sockaddr_in serverAddress, clientAddress;
    socklen_t sizeOfClientInfo = sizeof(clientAddress);
    // Set up the address struct for the server socket
    setupAddressStruct(&serverAddress, atoi(argv[1]));
    // Associate the socket to the port
    if (bind(listenSocket, 
         (struct sockaddr *)&serverAddress, 
         sizeof(serverAddress)) < 0){
    error(1, "ERROR on binding");
}
    // Start listening for connections
    // Allow up to 5 connections to queue up
    listen(listenSocket, 5);
    // Accept a connection, blocking if one is not available until one connects 
    while (1) {
        // Accept the connection request which creates a connection socket
        int connectionSocket = accept(listenSocket, 
            (struct sockaddr *)&clientAddress, 
            &sizeOfClientInfo);
        if (connectionSocket < 0)
            error(1, "ERROR on accept");

        int pid = fork();
        switch (pid) {
            case -1:
                error(1, "Unable to fork child");
                break;
            case 0:
                verifyClient(connectionSocket);
                otpEncryption(connectionSocket);
                exit(0);
            default:
                // Close the connection socket for this client 
                close(connectionSocket);
        }
    }
    // Closing the listening socket
    close(listenSocket);
    return 0;
}