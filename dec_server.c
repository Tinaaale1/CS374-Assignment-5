#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

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

// Decrypt: (ciphertext - key + 27) % 27
void decrypt(const char* ciphertext, const char* key, char* plaintext) {
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        int ct = charToInt(ciphertext[i]);
        int kt = charToInt(key[i]);
        // Add 27 before modulo to avoid negative values
        plaintext[i] = intToChar((ct - kt + 27) % 27);
    }
    plaintext[strlen(ciphertext)] = '\0';
}

// Safer recvUntilNewline reads one byte at a time until '\n'
int recvUntilNewline(int sockfd, char* buffer, size_t maxLen) {
    size_t total = 0;
    while (total < maxLen - 1) {
        char ch;
        ssize_t r = recv(sockfd, &ch, 1, 0);
        if (r <= 0) return 0;  // Connection closed or error
        if (ch == '\n') {
            buffer[total] = '\0';
            return 1;
        }
        buffer[total++] = ch;
    }
    buffer[maxLen - 1] = '\0';
    return 1;
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

void setupAddressStruct(struct sockaddr_in* address, int portNumber) {
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

void handleClient(int connectionSocket) {
    char buffer[MAX_BUFFER], key[MAX_BUFFER], plaintext[MAX_BUFFER];

    // Step 1: Handshake
    memset(buffer, 0, sizeof(buffer));
    if (!recvUntilNewline(connectionSocket, buffer, sizeof(buffer))) {
        fprintf(stderr, "dec_server: ERROR reading handshake\n");
        close(connectionSocket);
        exit(1);
    }
    if (strcmp(buffer, HANDSHAKE_MSG) != 0) {
        fprintf(stderr, "dec_server: ERROR invalid client\n");
        close(connectionSocket);
        exit(1);
    }

    // Send handshake ACK with newline
    char handshakeAckWithNewline[64];
    snprintf(handshakeAckWithNewline, sizeof(handshakeAckWithNewline), "%s\n", HANDSHAKE_ACK);
    if (sendAll(connectionSocket, handshakeAckWithNewline, strlen(handshakeAckWithNewline)) < 0) {
        fprintf(stderr, "dec_server: ERROR sending handshake ack\n");
        close(connectionSocket);
        exit(1);
    }

    // Step 2: Receive ciphertext
    memset(buffer, 0, sizeof(buffer));
    if (!recvUntilNewline(connectionSocket, buffer, sizeof(buffer))) {
        fprintf(stderr, "dec_server: ERROR reading ciphertext\n");
        close(connectionSocket);
        exit(1);
    }
    strcpy(plaintext, buffer);  // Temporarily store ciphertext in plaintext buffer

    // Step 3: Receive key
    memset(key, 0, sizeof(key));
    if (!recvUntilNewline(connectionSocket, key, sizeof(key))) {
        fprintf(stderr, "dec_server: ERROR reading key\n");
        close(connectionSocket);
        exit(1);
    }

    // Validate key length
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "dec_server: ERROR key too short\n");
        close(connectionSocket);
        exit(1);
    }

    // Step 4: Decrypt ciphertext using key
    char decrypted[MAX_BUFFER];
    memset(decrypted, 0, sizeof(decrypted));
    decrypt(plaintext, key, decrypted);
    strcat(decrypted, "\n");

    // Step 5: Send decrypted plaintext
    if (sendAll(connectionSocket, decrypted, strlen(decrypted)) < 0) {
        fprintf(stderr, "dec_server: ERROR sending decrypted text\n");
        close(connectionSocket);
        exit(1);
    }

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
    if (listenSocketFD < 0) error("dec_server: ERROR opening socket");

    int yes = 1;
    if (setsockopt(listenSocketFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
        error("dec_server: ERROR on setsockopt");

    setupAddressStruct(&serverAddress, atoi(argv[1]));

    if (bind(listenSocketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0)
        error("dec_server: ERROR on binding");

    listen(listenSocketFD, MAX_BACKLOG);

    while (1) {
        sizeOfClientInfo = sizeof(clientAddress);
        connectionSocketFD = accept(listenSocketFD, (struct sockaddr*)&clientAddress, &sizeOfClientInfo);
        if (connectionSocketFD < 0) {
            fprintf(stderr, "dec_server: ERROR on accept\n");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "dec_server: ERROR on fork\n");
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
