#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// Error helper
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Receive all bytes utility
ssize_t receive_all(int sockfd, char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = recv(sockfd, buf + total, len - total, 0);
        if (n <= 0) return n; // error or closed
        total += n;
    }
    return total;
}

// Send all bytes utility
ssize_t send_all(int sockfd, const char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = send(sockfd, buf + total, len - total, 0);
        if (n <= 0) return n; // error or closed
        total += n;
    }
    return total;
}

// Get string length function (simplified)
int get_length(const char* str) {
    int count = 0;
    while (str[count] != '\0') {
        count++;
    }
    return count;
}

// Decrypt message using key (same logic)
void decrypt_message(char* encrypted_text, char* decryption_key, char* output) {
    int length = get_length(encrypted_text);
    for (int i = 0; i < length; i++) {
        int cipher_val = (encrypted_text[i] == ' ') ? 26 : (encrypted_text[i] - 'A');
        int key_val = (decryption_key[i] == ' ') ? 26 : (decryption_key[i] - 'A');
        int plain_val = cipher_val - key_val;
        while (plain_val < 0) plain_val += 27;
        plain_val %= 27;
        output[i] = (plain_val == 26) ? ' ' : (char)(plain_val + 'A');
    }
    output[length] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "USAGE: %s port\n", argv[0]);
        exit(1);
    }

    int listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock < 0) error("ERROR opening socket");

    int yes = 1;
    if (setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0)
        error("ERROR setting socket options");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(atoi(argv[1]));
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listen_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
        error("ERROR on binding");

    listen(listen_sock, 5);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int comm_sock = accept(listen_sock, (struct sockaddr*)&client_addr, &client_len);
        if (comm_sock < 0) error("ERROR on accept");

        pid_t pid = fork();
        if (pid < 0) error("ERROR on fork");

        if (pid == 0) {  // Child process
            close(listen_sock);

            char op_code[4] = {0};
            if (receive_all(comm_sock, op_code, 3) <= 0) {
                close(comm_sock);
                exit(1);
            }

            if (strcmp(op_code, "DEC") != 0) {
                char err_msg[] = "ERROR";
                send_all(comm_sock, err_msg, sizeof(err_msg) - 1);
                close(comm_sock);
                exit(1);
            }

            char ok_msg[] = "OK";
            send_all(comm_sock, ok_msg, sizeof(ok_msg) - 1);

            int ciphertext_len = 0;
            if (receive_all(comm_sock, (char*)&ciphertext_len, sizeof(int)) <= 0) {
                close(comm_sock);
                exit(1);
            }

            char *ciphertext = calloc(ciphertext_len + 1, sizeof(char));
            if (!ciphertext) error("ERROR allocating memory for ciphertext");

            if (receive_all(comm_sock, ciphertext, ciphertext_len) <= 0) {
                free(ciphertext);
                close(comm_sock);
                exit(1);
            }
            ciphertext[ciphertext_len] = '\0';

            int key_len = 0;
            if (receive_all(comm_sock, (char*)&key_len, sizeof(int)) <= 0) {
                free(ciphertext);
                close(comm_sock);
                exit(1);
            }

            char *key = calloc(key_len + 1, sizeof(char));
            if (!key) {
                free(ciphertext);
                error("ERROR allocating memory for key");
            }

            if (receive_all(comm_sock, key, key_len) <= 0) {
                free(ciphertext);
                free(key);
                close(comm_sock);
                exit(1);
            }
            key[key_len] = '\0';

            char *plaintext = calloc(ciphertext_len + 1, sizeof(char));
            if (!plaintext) {
                free(ciphertext);
                free(key);
                error("ERROR allocating memory for plaintext");
            }

            decrypt_message(ciphertext, key, plaintext);

            // Send length and plaintext back
            if (send_all(comm_sock, (char*)&ciphertext_len, sizeof(int)) <= 0) {
                free(ciphertext);
                free(key);
                free(plaintext);
                close(comm_sock);
                exit(1);
            }

            if (send_all(comm_sock, plaintext, ciphertext_len) <= 0) {
                free(ciphertext);
                free(key);
                free(plaintext);
                close(comm_sock);
                exit(1);
            }

            free(ciphertext);
            free(key);
            free(plaintext);
            close(comm_sock);
            exit(0);
        } else {  // Parent process
            close(comm_sock);
        }
    }

    close(listen_sock);
    return 0;
}
