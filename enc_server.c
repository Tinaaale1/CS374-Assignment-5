#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>

#define MAX_BUFFER 150000
#define MAX_BACKLOG 5
#define HANDSHAKE_MSG "ENC_CLIENT"
#define HANDSHAKE_ACK "ENC_SERVER"

void error(const char* msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

int charToInt(char c) {
    return (c == ' ') ? 26 : c - 'A';
}

char intToChar(int i) {
    return (i == 26) ? ' ' : 'A' + i;
}

void encrypt(const char* plaintext, const char* key, char* ciphertext) {
    for (int i = 0; plaintext[i] != '\0'; i++) {
        int pt = charToInt(plaintext[i]);
        int kt = charToInt(key[i]);
        ciphertext[i] = intToChar((pt + kt) % 27);
    }
    ciphertext[strlen(plaintext)] = '\0';
}

ssize_t sendAll(int sockfd, const char* buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t sent = send(sockfd, buffer + total, length - total, 0);
        if (sent <= 0) return -1;
        total += sent;
    }
    return total;
}

void recvUntilNewline(int sockfd, char* buffer) {
    memset(buffer, 0, MAX_BUFFER);
    int total = 0;
    while (1) {
        char chunk[1024];
        memset(chunk, 0, sizeof(chunk));
        int n = recv(sockfd, chunk, sizeof(chunk) - 1, 0);
        if (n <= 0) break;
        for (int i = 0; i < n; i++) {
            if (chunk[i] == '\n') {
                strncat(buffer, chunk, i);
                return;
            }
        }
        strcat(buffer, chunk);
        total += n;
        if (total >= MAX_BUFFER - 1) break;
    }
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

void handleClient(int connectionSocket) {
    char buffer[MAX_BUFFER], key[MAX_BUFFER], ciphertext[MAX_BUFFER];

    // Step 1: Handshake
    memset(buffer, 0, sizeof(buffer));
    recvUntilNewline(connectionSocket, buffer);
    if (strcmp(buffer, HANDSHAKE_MSG) != 0) {
        fprintf(stderr, "enc_server: ERROR invalid client\n");
        close(connectionSocket);
        exit(1);
    }
    sendAll(connectionSocket, HANDSHAKE_ACK, strlen(HANDSHAKE_ACK));

    // Step 2: Receive plaintext
    memset(buffer, 0, sizeof(buffer));
    recvUntilNewline(connectionSocket, buffer);
    strcpy(buffer, strtok(buffer, "\n"));  // Remove newline
    char plaintext[MAX_BUFFER];
    strcpy(plaintext, buffer);

    // Step 3: Receive key
    memset(key, 0, sizeof(key));
    recvUntilNewline(connectionSocket, key);
    strcpy(key, strtok(key, "\n"));

    // 🔒 Step 3.5: Validate key length
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "enc_server: ERROR key too short\n");
        close(connectionSocket);
        exit(1);
    }

    // Step 4: Encrypt
    memset(ciphertext, 0, sizeof(ciphertext));
    encrypt(plaintext, key, ciphertext);
    strcat(ciphertext, "\n");

    // Step 5: Send ciphertext
    sendAll(connectionSocket, ciphertext, strlen(ciphertext));

    close(connectionSocket);
    exit(0);
}

int main(int argc, char* argv[]) {
    int listenSocketFD, connectionSocketFD;
    socklen_t sizeOfClientInfo;
    struct sockaddr_in serverAddress, clientAddress;

    if (argc < 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSocketFD < 0) error("enc_server: ERROR opening socket");

    int yes = 1;
    if (setsockopt(listenSocketFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
        error("enc_server: ERROR on setsockopt");

    setupAddressStruct(&serverAddress, atoi(argv[1]));

    if (bind(listenSocketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
        error("enc_server: ERROR on binding");

    listen(listenSocketFD, MAX_BACKLOG);

    while (1) {
        sizeOfClientInfo = sizeof(clientAddress);
        connectionSocketFD = accept(listenSocketFD, (struct sockaddr*)&clientAddress, &sizeOfClientInfo);
        if (connectionSocketFD < 0) {
            fprintf(stderr, "enc_server: ERROR on accept\n");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "enc_server: ERROR on fork\n");
            close(connectionSocketFD);
        } else if (pid == 0) {
            close(listenSocketFD);
            handleClient(connectionSocketFD);
        } else {
            close(connectionSocketFD);
            while (waitpid(-1, NULL, WNOHANG) > 0);
        }
    }

    close(listenSocketFD);
    return 0;
}
