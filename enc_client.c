#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 1024

int is_valid_text(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && !(text[i] >= 'A' && text[i] <= 'Z')) {
            return 0;
        }
    }
    return 1;
}

// Read from socket until newline or max_len-1 chars
ssize_t recv_until_newline(int sockfd, char *buf, size_t max_len) {
    size_t total = 0;
    while (total < max_len - 1) {
        char c;
        ssize_t n = recv(sockfd, &c, 1, 0);
        if (n <= 0) return n;
        if (c == '\n') break;
        buf[total++] = c;
    }
    buf[total] = '\0';
    return total;
}

int main(int argc, char *argv[]) {
    int clientsockfd, portnum;
    struct sockaddr_in server_addr;
    struct hostent *server;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    // Read plaintext file
    int plainfd = open(argv[1], O_RDONLY);
    if (plainfd < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }
    char plaintext[BUFFER_SIZE * 10] = {0};
    ssize_t plain_len = read(plainfd, plaintext, sizeof(plaintext) - 1);
    if (plain_len < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        close(plainfd);
        exit(1);
    }
    close(plainfd);
    plaintext[plain_len] = '\0';

    if (!is_valid_text(plaintext)) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    // Remove trailing newline
    if (plain_len > 0 && plaintext[plain_len - 1] == '\n') {
        plaintext[plain_len - 1] = '\0';
        plain_len--;
    }

    // Read key file
    int keyfd = open(argv[2], O_RDONLY);
    if (keyfd < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }
    char key[BUFFER_SIZE * 10] = {0};
    ssize_t key_len = read(keyfd, key, sizeof(key) - 1);
    if (key_len < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        close(keyfd);
        exit(1);
    }
    close(keyfd);
    key[key_len] = '\0';

    if (key_len > 0 && key[key_len - 1] == '\n') {
        key[key_len - 1] = '\0';
        key_len--;
    }

    if (key_len < plain_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    portnum = atoi(argv[3]);
    clientsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientsockfd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    server = gethostbyname("localhost");
    if (server == NULL) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(portnum);

    if (connect(clientsockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send authorization string with newline
    char auth_msg[] = "enc_d_bs\n";
    if (send(clientsockfd, auth_msg, strlen(auth_msg), 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    char auth_response[50];
    ssize_t n = recv_until_newline(clientsockfd, auth_response, sizeof(auth_response));
    if (n <= 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    if (strcmp(auth_response, "enc_d_bs") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send plaintext + newline
    char *plaintext_with_newline = malloc(plain_len + 2);
    memcpy(plaintext_with_newline, plaintext, plain_len);
    plaintext_with_newline[plain_len] = '\n';
    plaintext_with_newline[plain_len + 1] = '\0';

    if (send(clientsockfd, plaintext_with_newline, plain_len + 1, 0) < 0) {
        free(plaintext_with_newline);
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    free(plaintext_with_newline);

    // Send key (only plaintext length) + newline
    char *key_with_newline = malloc(plain_len + 2);
    memcpy(key_with_newline, key, plain_len);
    key_with_newline[plain_len] = '\n';
    key_with_newline[plain_len + 1] = '\0';

    if (send(clientsockfd, key_with_newline, plain_len + 1, 0) < 0) {
        free(key_with_newline);
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    free(key_with_newline);

    // Receive encrypted message until newline
    char ciphertext[BUFFER_SIZE * 20];
    n = recv_until_newline(clientsockfd, ciphertext, sizeof(ciphertext));
    if (n <= 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    printf("%s\n", ciphertext);

    close(clientsockfd);
    return 0;
}
