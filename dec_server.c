#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define BUFFER_SIZE 1000

int error(int exitCode, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Client error: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    exit(exitCode);
}

void setupAddressStruct(struct sockaddr_in* address, int portNumber){
    memset((char*) address, '\0', sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);
    address->sin_addr.s_addr = INADDR_ANY;
}

void sendData(int sock, char* data) {
    int len = (int)strlen(data);
    if (send(sock, &len, sizeof(len), 0) < 0)
        error(1, "Unable to write to socket");

    int charsSent;
    for (int i = 0; i < len; i += charsSent) {
        int remaining = len - i;
        charsSent = remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE;
        if (send(sock, data + i, charsSent, 0) < 0)
            error(1, "Unable to write to socket");
    }
}

char* receive(int sock) {
    int len;
    if (recv(sock, &len, sizeof(len), 0) < 0)
        error(1, "Unable to read from socket");

    char* result = malloc(len + 1);
    if (!result)
        error(1, "Unable to allocate memory");

    int charsRead;
    for (int i = 0; i < len; i += charsRead) {
        int size = len - i > BUFFER_SIZE - 1 ? BUFFER_SIZE - 1 : len - i;
        charsRead = (int)recv(sock, result + i, size, 0);
        if (charsRead < 0)
            error(1, "Unable to read from socket");
    }

    result[len] = '\0';
    return result;
}

void validate(int sock) {
    char client[4], server[4] = "dec";
    memset(client, '\0', sizeof(client));

    if (recv(sock, client, sizeof(client), 0) < 0)
        error(1, "Unable to read from socket");

    if (send(sock, server, sizeof(server), 0) < 0)
        error(1, "Unable to write to socket");

    if (strcmp(client, server)) {
        close(sock);
        error(2, "Client not dec_client");
    }
}

void handleOtpComm(int sock) {
    char* enc = receive(sock);
    char* key = receive(sock);
    int len = (int)strlen(enc);
    char* result = (char*) malloc(len + 1);

    for (int i = 0; i < len; i++) {
        int encVal = enc[i] == ' ' ? 26 : enc[i] - 'A';
        int keyVal = key[i] == ' ' ? 26 : key[i] - 'A';
        int txtVal = abs(encVal - keyVal + 27) % 27;
        result[i] = txtVal == 26 ? ' ' : txtVal + 'A';
    }
    result[len] = '\0';

    sendData(sock, result);
    free(result);
    free(enc);
    free(key);
    close(sock);
}

int main(int argc, const char * argv[]) {
    if (argc < 2)
        error(1, "USAGE: %s port\n", argv[0]);

    int listenSock = socket(AF_INET, SOCK_STREAM, 0);
    if (listenSock < 0)
        error(1, "Unable to open socket");

    struct sockaddr_in server, client;
    socklen_t clientSize = sizeof(client);
    setupAddressStruct(&server, atoi(argv[1]));

    if (bind(listenSock, (struct sockaddr *) &server, sizeof(server)) < 0)
        error(1, "Unable to bind socket");

    listen(listenSock, 5);
    while (1) {
        int sock = accept(listenSock, (struct sockaddr *)&client, &clientSize);
        if (sock < 0)
            error(1, "Unable to accept connection");

        int pid = fork();
        switch (pid) {
            case -1:
                error(1, "Unable to fork child");
                break;
            case 0:
                validate(sock);
                handleOtpComm(sock);
                exit(0);
            default:
                close(sock);
        }
    }

    close(listenSock);
    return 0;
}
