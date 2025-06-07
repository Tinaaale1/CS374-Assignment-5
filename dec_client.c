#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define CHUNK 1000

// Custom error handler with formatting
void fail(int code, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "Client error: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(code);
}

// Setup network address structure
void configureAddress(struct sockaddr_in* addr, int port, char* host) {
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    struct hostent* entry = gethostbyname(host);
    if (!entry) fail(0, "Host not found");
    memcpy(&addr->sin_addr.s_addr, entry->h_addr_list[0], entry->h_length);
}

// Send full string with length prefix
void push(int socketFD, char* message) {
    int length = strlen(message);
    if (send(socketFD, &length, sizeof(length), 0) < 0)
        fail(1, "Failed to write to socket");

    for (int i = 0; i < length;) {
        int part = length - i < CHUNK ? length - i : CHUNK;
        int sent = send(socketFD, message + i, part, 0);
        if (sent < 0) fail(1, "Failed to write to socket");
        i += sent;
    }
}

// Receive full message with length prefix
char* pull(int socketFD) {
    int total;
    if (recv(socketFD, &total, sizeof(total), 0) < 0)
        fail(1, "Failed to read from socket");

    char* buffer = malloc(total + 1);
    if (!buffer) fail(1, "Memory allocation failed");

    for (int i = 0; i < total;) {
        int part = total - i > CHUNK ? CHUNK : total - i;
        int received = recv(socketFD, buffer + i, part, 0);
        if (received < 0) fail(1, "Failed to read from socket");
        i += received;
    }
    buffer[total] = '\0';
    return buffer;
}

// Check that we are talking to a decryption server
void handshake(int socketFD) {
    char msg[] = "dec";
    char response[4] = {0};

    if (send(socketFD, msg, sizeof(msg), 0) < 0)
        fail(1, "Failed to write to socket");
    if (recv(socketFD, response, sizeof(response), 0) < 0)
        fail(1, "Failed to read from socket");

    if (strcmp(msg, response) != 0) {
        close(socketFD);
        fail(2, "Connected to wrong server");
    }
}

// Read file contents into buffer (only A-Z and space allowed)
char* readFile(char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) fail(0, "Cannot open file: %s", filename);

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* content = malloc(size);
    if (!content) {
        fclose(f);
        fail(0, "Memory allocation error");
    }

    for (int i = 0; i < size - 1; i++) {
        char ch = fgetc(f);
        if ((ch < 'A' || ch > 'Z') && ch != ' ')
            fail(0, "Invalid character in %s: %c (%d)", filename, ch, ch);
        content[i] = ch;
    }
    content[size - 1] = '\0';
    fclose(f);
    return content;
}

int main(int argc, char* argv[]) {
    if (argc != 4)
        fail(0, "USAGE: %s <plaintext> <key> <port>", argv[0]);

    char* ciphertext = readFile(argv[1]);
    char* key = readFile(argv[2]);

    if (strlen(ciphertext) > strlen(key))
        fail(0, "Key is too short for the given ciphertext");

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) fail(0, "Socket creation failed");

    struct sockaddr_in serverAddr;
    configureAddress(&serverAddr, atoi(argv[3]), "localhost");

    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
        fail(0, "Connection to server failed");

    handshake(sockfd);
    push(sockfd, ciphertext);
    push(sockfd, key);

    char* result = pull(sockfd);
    printf("%s\n", result);

    free(ciphertext);
    free(key);
    free(result);
    close(sockfd);
    return 0;
}
