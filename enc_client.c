
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  // ssize_t
#include <sys/socket.h> // send(),recv()
#include <netdb.h>      // gethostbyname()

/**
* Client code
* 1. Create a socket and connect to the server specified in the command arugments.
* 2. Prompt the user for input and send that input as a message to the server.
* 3. Print the message received from the server and exit the program.
*/

#define BUFFER_CAPACITY 1000

// Print formatted error message and exit with status code +
void error(int exitCode, const char *message) {
    fprintf(stderr, "Client error: %s\n", message);
    exit(exitCode);
}

// From client.c
// Set up the address struct 
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber, 
                        const char* hostname) {
    // Clear out the address struct
    memset(address, 0, sizeof(*address));
    // The address should be network capable
    address->sin_family = AF_INET;
    // Store the port number
    address->sin_port = htons(portNumber);
    // Get the DNS entry for this host name 
    struct hostent* hostInfo = gethostbyname(hostname);
    if (hostInfo == NULL)
        error(1, "CLIENT: ERROR, no such host");
    // Copy the first IP address from the DNS entry to sin_addr.s_addr
    memcpy((char*) &address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0], 
        hostInfo->h_length);
}

// Adapted from example code from Client Program section
// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397
// Functions reads a file path and returns the contents of the file as a string
char* receiveFilePath(const char* filepath) {
    // Open file in read mode 
    FILE* f = fopen(filepath, "r");
    if (!f)
        error(1, "Cannot open file");
    ssize_t capacity = 1024;
    // Track how many characters have been read
    ssize_t length = 0;
    // Allocates capcity bytes for the data buffer 
    char* data = malloc(capacity);
    if (!data) {
        fclose(f);
        error(1, "Memory allocation failed");
    }
    int ch;
    // Read one character at a time from file until end of file
    while ((ch = fgetc(f)) != EOF) {
        // Checks if the character is uppercase, space, or newline
        int isUppercase = (ch >= 'A') && (ch <= 'Z');
        int isSpace = (ch == ' ');
        int isNewline = (ch == '\n');
        // If the character is not valid, free memory and exit with error 
        if (!isUppercase && !isSpace && !isNewline) {
            free(data);
            fclose(f);
            error(1, "Invalid character in file");
        }
        // Skip newline characters 
        if (isNewline) 
            continue;
        // Checks if there is enough space to store more characters
        if (length + 1 >= capacity) {
            // Double capacity for more characters
            capacity *= 2;
            char* newData = realloc(data, capacity);
            if (!newData) {
                free(data);
                fclose(f);
                error(1, "Memory allocation failed");
            }
            // Update data to point the new memory 
            data = newData;
        }
        // Store the valid character into data 
        data[length] = (char)ch;
        // Increment length by 1 for the next character
        length++;
    }
    // Adds the null terminator to the end of the string stored
    data[length] = '\0';
    fclose(f);
    return data;
}

// Code adapted from the code in Server Program section
// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397
void sendData(int connectionSocket, char* data) {
    // Calculate the number of characters 
    int len = strlen(data);
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
            if (len - totalSent < BUFFER_CAPACITY) {
                bytesToSend = len - totalSent;
            } else {
                bytesToSend = BUFFER_CAPACITY;
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

// Code adapted from the code Server Program section 
// https://canvas.oregonstate.edu/courses/1999732/pages/exploration-client-server-communication-via-sockets?module_item_id=25329397
char* receiveData(int connectionSocket) {
    int len;
    int charsRead;
    // Receive the length of the incoming message
    // If negative value then error occurred
    charsRead = recv(connectionSocket, &len, sizeof(len), 0);
    // If negative value then error occurred
    if (charsRead < 0) {
        error(1, "CLIENT: ERROR reading from socket");
    }

    char* result = malloc(len + 1);  // Allocate buffer for incoming message
    if (!result) {
        error(1, "CLIENT: Memory allocation failed");
    }

    // Track how many bytes have been read
    int totalRead = 0;
    // Loop until all expected bytes are received
    while (totalRead < len) {
        int bytesToRead;
        if (len - totalRead < BUFFER_CAPACITY) {
            bytesToRead = len - totalRead;
        } else {
            bytesToRead = BUFFER_CAPACITY;
        }
        charsRead = recv(connectionSocket, result + totalRead, bytesToRead, 0);
        if (charsRead < 0) {
            error(1, "CLIENT: ERROR reading from socket");
        }
        // Updates how many bytes were successfully read
        totalRead += charsRead;
    }
    result[len] = '\0'; 
    return result;
}

// Adapted code for the validation logic
// https://github.com/CS-344-nilsstreedain/program4/blob/main/enc_client.c
// Verify the server
// Takes a socket descriptor that represents the network connection
void verifyServer(int connectionSocket) {
    // Hanshake identifier 
    char id[] = "enc";
    char response[4] = {0};
    // Sends handshake message to the server via the socket
    if (send(connectionSocket, id, sizeof(id), 0) < 0)
        error(1, "Failed to send handshake");
    // Receives handshake response from server
    if (recv(connectionSocket, response, sizeof(response), 0) < 0)
        error(1, "Failed to receive handshake");
    // Compares the "enc" string with the received response
    if (strcmp(id, response) != 0) {
        close(connectionSocket);
        error(2, "Connected to incompatible server");
    }
}

// plaintext is the name of a file in the current directory that contains the plaintext to encrpy 
// key contains the encryption key to use to encrypt the text 
// portNumber used to attempt to enc_server on
// From client.c 
int main(int argc, const char* argv[]) {
    int socketFD, charsWritten, charsRead;
    // Checks if the user provided program name, plaintext file, key file, and port number
    if (argc != 4)
        error(1, "Usage: ./enc_client <plaintext> <key> <portNumber>");
    // Calls receiveFilePath() to read the plaintext file
    char* plaintext = receiveFilePath(argv[1]);
    // Calls receiveFilePath() to read the key file
    char* key = receiveFilePath(argv[2]);
    if (strlen(key) < strlen(plaintext))
        error(1, "Key is shorter than plaintext");
    // Create the socket that will listen for connections
    socketFD = socket(AF_INET, SOCK_STREAM, 0); 
    if (socketFD < 0){
        error(1, "CLIENT: ERROR opening socket");
    }
    struct sockaddr_in serverAddress;
    // Set up the server address struct 
    setupAddressStruct(&serverAddress, atoi(argv[3]), "localhost");
    // Connect to the server
    if (connect(socketFD, 
        (struct sockaddr*)&serverAddress, 
        sizeof(serverAddress)) < 0)
        error(1, "CLIENT: ERROR connecting");
    verifyServer(socketFD);
    sendData(socketFD, plaintext);
    sendData(socketFD, key);
    // Prints the encrypted ciphertext 
    char* encrypted = receiveData(socketFD);
    printf("%s\n", encrypted);

    free(plaintext);
    free(key);
    free(encrypted);
    close(socketFD);
    return 0;
}
