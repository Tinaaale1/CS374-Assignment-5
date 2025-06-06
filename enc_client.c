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
    int saved_errno = errno;
    while(waitpid(-1, NULL, WNOHANG) > 0);
    errno = saved_errno;
}

// Encrypt message
void encrypt_message(char* plaintext, char* key, char* ciphertext) {
    int pt_len = strlen(plaintext);
    int key_len = strlen(key);

    for (int i = 0; i < pt_len && i < key_len; i++) {
        int plain_num = (plaintext[i] == ' ') ? 26 : (plaintext[i] - 'A');
        int key_num = (key[i] == ' ') ? 26 : (key[i] - 'A');

        int sum = (plain_num ^ key_num) + 2 * (plain_num & key_num);
        int encoded_digit = sum % 27;

        ciphertext[i] = (encoded_digit == 26) ? ' ' : (char)(encoded_digit + 'A');
    }
    ciphertext[pt_len] = '\0';
}

// Read exactly length bytes from sockfd into buffer
ssize_t recv_all(int sockfd, char *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t n = recv(sockfd, buffer + total, length - total, 0);
        if (n <= 0) return n;
        total += n;
    }
    return total;
}

// Send null-terminated string plus newline
ssize_t send_line(int sockfd, const char *msg) {
    size_t len = strlen(msg);
    char buf[len + 2];
    strcpy(buf, msg);
    buf[len] = '\n';
    buf[len+1] = '\0';
    return send(sockfd, buf, len + 1, 0);  // send including newline but not null terminator
}

// Receive a line (ending in \n) into buffer, replacing \n with '\0'
ssize_t recv_line(int sockfd, char *buffer, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1) {
        char c;
        ssize_t n = recv(sockfd, &c, 1, 0);
        if (n <= 0) return n;
        if (c == '\n') break;
        buffer[i++] = c;
    }
    buffer[i] = '\0';
    return i;
}

int main(int argc, char *argv[]) {
    if (argc != 2) error_exit("Usage: enc_server port", 1);

    int port_number = atoi(argv[1]);
    int listen_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    // Setup SIGCHLD handler
    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // Create socket
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) error_exit("Error opening socket", 1);

    // Set SO_REUSEADDR
    int yes = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("setsockopt");
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port_number);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        error_exit("Error on binding", 1);

    if (listen(listen_fd, 5) < 0)
        error_exit("Error on listen", 1);

    while (1) {
        client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("Error on accept");
            continue;
        }

        pid_t pid = fork();
        if (pid < 0) {
            perror("Error on fork");
            close(client_fd);
            continue;
        }

        if (pid == 0) {
            close(listen_fd);

            // Step 1: Receive client ID line (with \n)
            char buffer[100];
            ssize_t n = recv_line(client_fd, buffer, sizeof(buffer));
            if (n <= 0) {
                close(client_fd);
                exit(1);
            }

            // Verify client ID
            if (strcmp(buffer, "enc_client") != 0) {
                send_line(client_fd, "reject");
                close(client_fd);
                exit(2);
            }

            // Accept client
            send_line(client_fd, "accept");

            // Step 2: Receive plaintext size line
            n = recv_line(client_fd, buffer, sizeof(buffer));
            if (n <= 0) {
                close(client_fd);
                exit(1);
            }
            int pt_size = atoi(buffer);

            // Ack plaintext size
            send_line(client_fd, "size_received");

            // Step 3: Receive plaintext bytes
            char plaintext[MAX_BUFFER];
            if (recv_all(client_fd, plaintext, pt_size) <= 0) {
                close(client_fd);
                exit(1);
            }
            plaintext[pt_size] = '\0';

            // Ack plaintext received
            send_line(client_fd, "size_received");

            // Step 4: Receive key size line
            n = recv_line(client_fd, buffer, sizeof(buffer));
            if (n <= 0) {
                close(client_fd);
                exit(1);
            }
            int key_size = atoi(buffer);

            // Ack key size
            send_line(client_fd, "size_received");

            // Step 5: Receive key bytes
            char key[MAX_BUFFER];
            if (recv_all(client_fd, key, key_size) <= 0) {
                close(client_fd);
                exit(1);
            }
            key[key_size] = '\0';

            // Encrypt
            char ciphertext[MAX_BUFFER];
            encrypt_message(plaintext, key, ciphertext);

            // Step 6: Send ciphertext bytes
            size_t ct_len = strlen(ciphertext);
            size_t total_sent = 0;
            while (total_sent < ct_len) {
                ssize_t sent = send(client_fd, ciphertext + total_sent, ct_len - total_sent, 0);
                if (sent <= 0) break;
                total_sent += sent;
            }

            close(client_fd);
            exit(0);
        } else {
            close(client_fd);
        }
    }

    close(listen_fd);
    return 0;
}
