#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 150000

// Function to check if the input text contains only valid characters (A-Z and space)
int is_valid_text(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && !(text[i] >= 'A' && text[i] <= 'Z')) {
            return 0;
        }
    }
    return 1;
}

int main(int argc, char *argv[]) {
    int clientsockfd, portnum;
    struct sockaddr_in server_addr;
    struct hostent *server;

    if (argc < 4) {
        fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]);
        exit(1);
    }

    // Open plaintext file
    int plainfd = open(argv[1], O_RDONLY);
    if (plainfd < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    // Read plaintext into buffer
    char plaintext[BUFFER_SIZE] = {0};
    ssize_t plain_len = read(plainfd, plaintext, sizeof(plaintext) - 1);
    if (plain_len < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        close(plainfd);
        exit(1);
    }
    plaintext[plain_len] = '\0';
    close(plainfd);

    // Remove trailing newline if present
    if (plain_len > 0 && plaintext[plain_len - 1] == '\n') {
        plaintext[plain_len - 1] = '\0';
        plain_len--;
    }

    // Validate plaintext characters
    if (!is_valid_text(plaintext)) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    // Open key file
    int keyfd = open(argv[2], O_RDONLY);
    if (keyfd < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    // Read key into buffer
    char key[BUFFER_SIZE] = {0};
    ssize_t key_len = read(keyfd, key, sizeof(key) - 1);
    if (key_len < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        close(keyfd);
        exit(1);
    }
    key[key_len] = '\0';
    close(keyfd);

    // Remove trailing newline if present
    if (key_len > 0 && key[key_len - 1] == '\n') {
        key[key_len - 1] = '\0';
        key_len--;
    }

    // Check key length against plaintext length
    if (key_len < plain_len) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    // Setup socket connection to server
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

    // Send authorization message to server WITH newline
    char auth_msg[] = "enc_d_bs\n"; // Note the newline added
    ssize_t sent = send(clientsockfd, auth_msg, strlen(auth_msg), 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Wait for server response to authorization (expecting "enc_d_bs\n")
    char auth_response[20] = {0};
    ssize_t recvd = recv(clientsockfd, auth_response, sizeof(auth_response) - 1, 0);
    if (recvd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    auth_response[recvd] = '\0';

    if (strcmp(auth_response, "enc_d_bs\n") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send plaintext WITH newline
    char plaintext_msg[BUFFER_SIZE + 2];
    snprintf(plaintext_msg, sizeof(plaintext_msg), "%s\n", plaintext);
    sent = send(clientsockfd, plaintext_msg, strlen(plaintext_msg), 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send key WITH newline (only send key length equal to plaintext length)
    char key_msg[BUFFER_SIZE + 2];
    snprintf(key_msg, sizeof(key_msg), "%.*s\n", (int)plain_len, key);
    sent = send(clientsockfd, key_msg, strlen(key_msg), 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Receive encrypted ciphertext from server (until newline)
    char ciphertext[BUFFER_SIZE] = {0};
    size_t total_received = 0;
    while (1) {
        recvd = recv(clientsockfd, ciphertext + total_received, 1, 0);
        if (recvd <= 0) break;
        if (ciphertext[total_received] == '\n') {
            ciphertext[total_received] = '\0';
            break;
        }
        total_received += recvd;
    }

    if (total_received == 0) {
        fprintf(stderr, "Error: no ciphertext received from server\n");
        exit(1);
    }

    // Output ciphertext exactly (no extra newline)
    printf("%s\n", ciphertext);

    close(clientsockfd);

    return 0;
}
