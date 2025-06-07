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

void reportError(int code, const char* msg, ...) {
    va_list args;
    va_start(args, msg);
    fprintf(stderr, "enc_client error: ");
    vfprintf(stderr, msg, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(code);
}

void initServerAddress(struct sockaddr_in* serverAddr, int port, const char* hostname) {
    memset(serverAddr, 0, sizeof(*serverAddr));
    serverAddr->sin_family = AF_INET;
    serverAddr->sin_port = htons(port);
    
    struct hostent* host = gethostbyname(hostname);
    if (!host)
        reportError(1, "Unknown host %s", hostname);

    memcpy(&serverAddr->sin_addr.s_addr, host->h_addr_list[0], host->h_length);
}

char* loadFile(const char* filepath) {
    FILE* f = fopen(filepath, "r");
    if (!f)
        reportError(1, "Cannot open file: %s", filepath);

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f) - 1;
    rewind(f);

    char* data = malloc(len + 1);
    if (!data)
        reportError(1, "Memory allocation failed");

    for (size_t i = 0; i < len; i++) {
        char ch = fgetc(f);
        if ((ch < 'A' || ch > 'Z') && ch != ' ') {
            free(data);
            fclose(f);
            reportError(1, "Invalid character in %s: %c (ASCII %d)", filepath, ch, ch);
        }
        data[i] = ch;
    }
    data[len] = '\0';

    fclose(f);
    return data;
}

void sendAll(int sockfd, const char* data) {
    int len = strlen(data);
    if (send(sockfd, &len, sizeof(len), 0) < 0)
        reportError(1, "Failed to send data length");

    int total = 0;
    while (total < len) {
        int toSend = len - total < MAX_BUFFER ? len - total : MAX_BUFFER;
        int bytesSent = send(sockfd, data + total, toSend, 0);
        if (bytesSent < 0)
            reportError(1, "Failed to send data");
        total += bytesSent;
    }
}

char* receiveAll(int sockfd) {
    int len;
    if (recv(sockfd, &len, sizeof(len), 0) < 0)
        reportError(1, "Failed to read message length");

    char* buffer = malloc(len + 1);
    if (!buffer)
        reportError(1, "Memory allocation failed");

    int total = 0;
    while (total < len) {
        int chunk = len - total < MAX_BUFFER - 1 ? len - total : MAX_BUFFER - 1;
        int bytesRead = recv(sockfd, buffer + total, chunk, 0);
        if (bytesRead < 0)
            reportError(1, "Failed to receive data");
        total += bytesRead;
    }
    buffer[len] = '\0';
    return buffer;
}

void performHandshake(int sockfd) {
    char id[] = "enc";
    char response[4] = {0};

    if (send(sockfd, id, sizeof(id), 0) < 0)
        reportError(1, "Failed to send handshake");

    if (recv(sockfd, response, sizeof(response), 0) < 0)
        reportError(1, "Failed to receive handshake");

    if (strcmp(id, response) != 0) {
        close(sockfd);
        reportError(2, "Connected to incompatible server");
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4)
        reportError(1, "Usage: %s <plaintext> <key> <port>", argv[0]);

    char* text = loadFile(argv[1]);
    char* key = loadFile(argv[2]);

    if (strlen(key) < strlen(text))
        reportError(1, "Key is shorter than plaintext");

    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0)
        reportError(1, "Socket creation failed");

    struct sockaddr_in serverAddress;
    initServerAddress(&serverAddress, atoi(argv[3]), "localhost");

    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
        reportError(1, "Failed to connect to server");

    performHandshake(socketFD);
    sendAll(socketFD, text);
    sendAll(socketFD, key);

    char* encrypted = receiveAll(socketFD);
    printf("%s\n", encrypted);

    free(text);
    free(key);
    free(encrypted);
    close(socketFD);
    return 0;
}
