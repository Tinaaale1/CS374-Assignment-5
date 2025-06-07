#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

#define MAX_BUFFER 1000

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
    memcpy(&address->sin_addr.s_addr, 
        hostInfo->h_addr_list[0], 
        hostInfo->h_length);
}

// Functions a file path adn returns the contents of the file as a string
char* loadFile(const char* filepath) {
    // Open file in read mode 
    FILE* f = fopen(filepath, "r");
    if (!f)
        error(1, "Cannot open file");
    size_t capacity = 1024;
    // Track how many characters have been read
    size_t length = 0;
    // Allocates capcity bytes for the data buffer 
    char* data = malloc(capacity);
    if (!data) {
        fclose(f);
        error(1, "Memory allocation failed");
    }

    int ch;
    // Reads one charcter at a time until EOF
    while ((ch = fgetc(f)) != EOF) {
        // Checks if the character read is valid 
        if (ch < 'A') {
            // Checks if the character is not a space and not a newline
            if (ch != ' ' && ch != '\n') {
                free(data);
                fclose(f);
                error(1, "Invalid character in file");
            }
        } else {
            // Characters greater than Z are invalid 
            if (ch > 'Z') {
                if (ch != ' ' && ch != '\n') {
                    free(data);
                    fclose(f);
                    error(1, "Invalid character in file");
                }
            }
        // Skip newline characters 
        if (ch == '\n') {
            continue;
        }
        // Checks if the buffer needs to be resized to add more characters
        if (length + 1 >= capacity) {
            // If not enoguh then double the capacity
            capacity *= 2;
            char* newData = realloc(data, capacity);
            if (!newData) {
                free(data);
                fclose(f);
                error(1, "Memory allocation failed");
            }
            // Assign the resized buffer back to the data pointer
            data = newData;
        }
        data[length] = (char)ch;
        length++;
    }
}
    // Null-terminate the string
    data[length] = '\0';

    fclose(f);
    return data;
}

void sendData(int connectionSocket, char* data) {
    int len = strlen(data);
    // Sends the length of data over the socket to receiver 
    if (send(connectionSocket, &len, sizeof(len), 0) < 0)
        error(1, "CLIENT: ERROR writing to socket");
    // Keep track of how many bytes have been sent
    int totalSent = 0;
    // Loops until all bytes of the string are sent 
    while (totalSent < len) {
        int bytesToSend;
        if (len - totalSent < MAX_BUFFER) {
            bytesToSend = len - totalSent;
        } else {
            bytesToSend = MAX_BUFFER;
        }
        // Send message through the socket
        int bytesSent = send(connectionSocket, data + totalSent, bytesToSend, 0);
        if (bytesSent < 0)
            error(1, "CLIENT: WARNING: Not all data written to socket!");
        // Updates how many bytes were successfully sent
        totalSent += bytesSent;
    }
}

char* receiveAll(int connectionSocket) {
    int len;
    if (recv(connectionSocket, &len, sizeof(len), 0) < 0)
        error(1, "Failed to read message length");

    char* buffer = malloc(len + 1);
    if (!buffer)
        error(1, "Memory allocation failed");

    int totalSent = 0;
    while (totalSent < len) {
        int chunk = len - totalSent < MAX_BUFFER - 1 ? len - totalSent : MAX_BUFFER - 1;
        int bytesRead = recv(connectionSocket, buffer + totalSent, chunk, 0);
        if (bytesRead < 0)
            error(1, "Failed to receive data");
        totalSent += bytesRead;
    }
    buffer[len] = '\0';
    return buffer;
}

void performHandshake(int connectionSocket) {
    char id[] = "enc";
    char response[4] = {0};

    if (send(connectionSocket, id, sizeof(id), 0) < 0)
        error(1, "Failed to send handshake");

    if (recv(connectionSocket, response, sizeof(response), 0) < 0)
        error(1, "Failed to receive handshake");

    if (strcmp(id, response) != 0) {
        close(connectionSocket);
        error(2, "Connected to incompatible server");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4)
        error(1, "Usage: ./enc_client <plaintext> <key> <portNumber>");

    char* text = loadFile(argv[1]);
    char* key = loadFile(argv[2]);

    if (strlen(key) < strlen(text))
        error(1, "Key is shorter than plaintext");

    int connectionSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (connectionSocket < 0)
        error(1, "Socket creation failed");

    struct sockaddr_in address;
    setupAddressStruct(&address, atoi(argv[3]), "localhost");

    if (connect(connectionSocket, (struct sockaddr*)&address, sizeof(address)) < 0)
        error(1, "Failed to connect to server");

    performHandshake(connectionSocket);
    sendData(connectionSocket, text);
    sendData(connectionSocket, key);

    char* encrypted = receiveAll(connectionSocket);
    printf("%s\n", encrypted);

    free(text);
    free(key);
    free(encrypted);
    close(connectionSocket);
    return 0;
}
