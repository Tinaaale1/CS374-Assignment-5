#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#define MAX_BUFFER 150000

// Error exit function
void error_exit(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// SIGCHLD handler to reap zombie child processes
void sigchld_handler(int s) {
    // waitpid() might overwrite errno, so save and restore it
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// Encryption function
void encrypt_message(char* plaintext, char* key, char* ciphertext) {
    int pt_len = 0, key_len = 0;

    while (plaintext[pt_len] != '\0') pt_len++;
    while (key[key_len] != '\0') key_len++;

    int i = 0;
    for (; i < pt_len && i < key_len; i++) {
        int plain_num = (plaintext[i] == ' ') ? 26 : (plaintext[i] - 'A');
        int key_num = (key[i] == ' ') ? 26 : (key[i] - 'A');

        // Encoding formula as given
        int sum = (plain_num ^ key_num) + 2 * (plain_num & key_num);
        int encoded_digit = sum % 27;

        ciphertext[i] = (encoded_digit == 26) ? ' ' : (char)(encoded_digit + 'A');
    }
    ciphertext[i] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(1);
    }

    int port_number = atoi(argv[1]);
    int listen_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    char buffer[MAX_BUFFER];
    char key[MAX_BUFFER];
    char ciphertext[MAX_BUFFER];

    // Setup SIGCHLD handler to reap zombies
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART; // Restart interrupted syscalls
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // Create socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) error_exit("Error opening socket", 1);

    // Set SO_REUSEADDR to reuse port immediately after program exit
    int yes = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        // Not fatal; continue anyway
    }

    // Setup address struct
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_number);

    // Bind socket
    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        error_exit("Error on binding", 1);

    // Listen for connections
    if (listen(listen_fd, 5) < 0)
        error_exit("Error on listen", 1);

    while (1) {
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Error on accept");
            continue;
        }

        // Fork a child to handle client
        pid_t pid = fork();
        if (pid < 0) {
            perror("Error on fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            // Child process
            close(listen_fd);

            // Receive client identification
            memset(buffer, 0, sizeof(buffer));
            int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received < 0) {
                perror("Error reading from socket");
                close(client_fd);
                exit(1);
            }
            buffer[bytes_received] = '\0';

            // Check client ID: should be "enc_client"
            if (strcmp(buffer, "enc_client") != 0) {
                const char *msg = "reject";
                send(client_fd, msg, strlen(msg), 0);
                close(client_fd);
                exit(2);
            }

            // Accept client
            const char *msg = "accept";
            send(client_fd, msg, strlen(msg), 0);

            // Receive plaintext size
            memset(buffer, 0, sizeof(buffer));
            bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                perror("Error reading plaintext size");
                close(client_fd);
                exit(1);
            }
            buffer[bytes_received] = '\0';
            int plaintext_size = atoi(buffer);

            // Send acknowledgment
            const char *ack = "size_received";
            send(client_fd, ack, strlen(ack), 0);

            // Receive plaintext in chunks until full size received
            int total_received = 0;
            memset(buffer, 0, sizeof(buffer));
            while (total_received < plaintext_size) {
                bytes_received = recv(client_fd, buffer + total_received, plaintext_size - total_received, 0);
                if (bytes_received <= 0) {
                    perror("Error receiving plaintext");
                    close(client_fd);
                    exit(1);
                }
                total_received += bytes_received;
            }
            buffer[plaintext_size] = '\0';  // Null terminate plaintext

            // Send acknowledgment for plaintext
            send(client_fd, ack, strlen(ack), 0);

            // Receive key size
            memset(buffer, 0, sizeof(buffer));
            bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received <= 0) {
                perror("Error reading key size");
                close(client_fd);
                exit(1);
            }
            buffer[bytes_received] = '\0';
            int key_size = atoi(buffer);

            // Send acknowledgment
            send(client_fd, ack, strlen(ack), 0);

            // Receive key in chunks until full key received
            total_received = 0;
            memset(key, 0, sizeof(key));
            while (total_received < key_size) {
                bytes_received = recv(client_fd, key + total_received, key_size - total_received, 0);
                if (bytes_received <= 0) {
                    perror("Error receiving key");
                    close(client_fd);
                    exit(1);
                }
                total_received += bytes_received;
            }
            key[key_size] = '\0';

            // Encrypt the message
            encrypt_message(buffer, key, ciphertext);

            // Send encrypted ciphertext
            int ciphertext_len = strlen(ciphertext);
            int total_sent = 0;
            while (total_sent < ciphertext_len) {
                int sent = send(client_fd, ciphertext + total_sent, ciphertext_len - total_sent, 0);
                if (sent <= 0) {
                    perror("Error sending ciphertext");
                    break;
                }
                total_sent += sent;
            }

            close(client_fd);
            exit(0);
        } else {
            // Parent process closes client socket and continues
            close(client_fd);
            // Parent loops to accept new connections
        }
    }

    // Cleanup: close listening socket (never reached)
    close(listen_fd);
    return 0;
}
