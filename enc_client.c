#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 150000  // Large enough buffer for plaintext, key, ciphertext

// Check if input text contains only valid characters (A-Z and space)
int is_valid_text(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && !(text[i] >= 'A' && text[i] <= 'Z') && text[i] != '\n') {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
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
    char plaintext[BUFFER_SIZE] = {0};
    ssize_t plain_len = read(plainfd, plaintext, sizeof(plaintext) - 1);
    if (plain_len < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        close(plainfd);
        exit(1);
    }
    close(plainfd);

    // Remove trailing newline if present
    if (plaintext[plain_len - 1] == '\n') {
        plaintext[plain_len - 1] = '\0';
        plain_len--;
    } else {
        plaintext[plain_len] = '\0';
    }

    // Validate plaintext
    if (!is_valid_text(plaintext)) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    // Read key file
    int keyfd = open(argv[2], O_RDONLY);
    if (keyfd < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }
    char key[BUFFER_SIZE] = {0};
    ssize_t key_len = read(keyfd, key, sizeof(key) - 1);
    if (key_len < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        close(keyfd);
        exit(1);
    }
    close(keyfd);

    // Remove trailing newline from key if present
    if (key[key_len - 1] == '\n') {
        key[key_len - 1] = '\0';
        key_len--;
    } else {
        key[key_len] = '\0';
    }

    if (key_len < plain_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    int portnum = atoi(argv[3]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    struct hostent *server = gethostbyname("localhost");
    if (server == NULL) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    serv_addr.sin_port = htons(portnum);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send authorization string with newline
    char auth_msg[] = "enc_d_bs\n";
    if (send(sockfd, auth_msg, strlen(auth_msg), 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Receive authorization response
    char auth_response[20] = {0};
    ssize_t recvd = recv(sockfd, auth_response, sizeof(auth_response) - 1, 0);
    if (recvd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    auth_response[recvd] = '\0';

    if (strcmp(auth_response, "enc_d_bs\n") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send plaintext with newline
    if (send(sockfd, plaintext, plain_len, 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    if (send(sockfd, "\n", 1, 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send key with newline (only plaintext length)
    if (send(sockfd, key, plain_len, 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    if (send(sockfd, "\n", 1, 0) < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Receive ciphertext from server
    char ciphertext[BUFFER_SIZE] = {0};
    size_t total_received = 0;
    while (total_received < (size_t)plain_len) {
        recvd = recv(sockfd, ciphertext + total_received, plain_len - total_received, 0);
        if (recvd < 0) {
            fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
            exit(2);
        }
        if (recvd == 0) break;  // connection closed
        total_received += recvd;
    }

    // Close socket
    close(sockfd);

    // Ensure ciphertext is null-terminated for safety
    ciphertext[plain_len] = '\0';

    // Write ciphertext to file named "ciphertext1"
    FILE *out = fopen("ciphertext1", "w");
    if (out == NULL) {
        fprintf(stderr, "Error: could not write ciphertext1\n");
        exit(1);
    }
    fwrite(ciphertext, sizeof(char), plain_len, out);
    fclose(out);

    return 0;
}
