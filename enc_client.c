#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFFER_SIZE 1024

// Function to check if the input text contains only valid characters (A-Z and space)
int is_valid_text(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && !(text[i] >= 'A' && text[i] <= 'Z') && text[i] != '\n') {
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
    char plaintext[BUFFER_SIZE * 10] = {0};  // adjust size if needed
    ssize_t plain_len = read(plainfd, plaintext, sizeof(plaintext) - 1);
    if (plain_len < 0) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        close(plainfd);
        exit(1);
    }
    plaintext[plain_len] = '\0';
    close(plainfd);

    // Validate plaintext characters
    if (!is_valid_text(plaintext)) {
        fprintf(stderr, "enc_client error: input contains bad characters\n");
        exit(1);
    }

    // Remove trailing newline if present (common in text files)
    if (plaintext[plain_len - 1] == '\n') {
        plaintext[plain_len - 1] = '\0';
        plain_len--;
    }

    // Open key file
    int keyfd = open(argv[2], O_RDONLY);
    if (keyfd < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        exit(1);
    }

    // Read key into buffer
    char key[BUFFER_SIZE * 10] = {0};
    ssize_t key_len = read(keyfd, key, sizeof(key) - 1);
    if (key_len < 0) {
        fprintf(stderr, "Error: key '%s' is too short\n", argv[2]);
        close(keyfd);
        exit(1);
    }
    key[key_len] = '\0';
    close(keyfd);

    // Remove trailing newline from key if present
    if (key[key_len - 1] == '\n') {
        key[key_len - 1] = '\0';
        key_len--;
    }

    // Check key length against plaintext length
    if (key_len < plain_len) {
        fprintf(stderr, "Error: key ‘%s’ is too short\n", argv[2]);
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

    // Send authorization message to server
    char auth_msg[] = "enc_d_bs"; // Authorization string expected by server
    ssize_t sent = send(clientsockfd, auth_msg, strlen(auth_msg), 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Wait for server response to authorization
    char auth_response[20] = {0};
    ssize_t recvd = recv(clientsockfd, auth_response, sizeof(auth_response) - 1, 0);
    if (recvd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    auth_response[recvd] = '\0';

    if (strcmp(auth_response, "enc_d_bs") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send plaintext to server
    sent = send(clientsockfd, plaintext, plain_len, 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Send key to server
    sent = send(clientsockfd, key, plain_len, 0);
    if (sent < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }

    // Receive encrypted ciphertext from server
    char ciphertext[BUFFER_SIZE * 20] = {0};
    recvd = recv(clientsockfd, ciphertext, sizeof(ciphertext) - 1, 0);
    if (recvd < 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", portnum);
        exit(2);
    }
    ciphertext[recvd] = '\0';

    // Output ciphertext (exactly as expected, no extra messages)
    printf("%s\n", ciphertext);

    close(clientsockfd);

    return 0;
}
