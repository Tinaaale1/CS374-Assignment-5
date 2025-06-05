#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

// Print error and exit with given code
void errorExit(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// Get file size by reading bytes
int get_file_size_from_read(const char *filename) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR opening file %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    int count = 0;
    char ch;
    while (read(fd, &ch, 1) > 0) {
        count++;
    }
    close(fd);
    return count;
}

// Send entire file contents over socket
void sendFile(const char *filename, int sockfd) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR opening file %s\n", filename);
        exit(1);
    }

    char buffer[100000];
    ssize_t bytes_read;
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        ssize_t total_written = 0;
        while (total_written < bytes_read) {
            ssize_t bytes_written = write(sockfd, buffer + total_written, bytes_read - total_written);
            if (bytes_written < 0) {
                fprintf(stderr, "Client: ERROR writing to socket: %s\n", strerror(errno));
                close(fd);
                exit(1);
            }
            total_written += bytes_written;
        }
    }
    if (bytes_read < 0) {
        fprintf(stderr, "Client: ERROR reading file %s: %s\n", filename, strerror(errno));
        close(fd);
        exit(1);
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    int clientsockfd, portnum;
    struct sockaddr_in server_addr;
    struct hostent *server;
    char buffer[100000];
    const char hostname[] = "localhost";

    if (argc != 4) {
        fprintf(stderr, "usage %s <inputfile> <key> <port>\n", argv[0]);
        exit(1);
    }

    portnum = atoi(argv[3]);
    clientsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientsockfd < 0) {
        fprintf(stderr, "Client: ERROR opening socket\n");
        exit(1);
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Client: ERROR, no such host\n");
        exit(2);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(portnum);

    if (connect(clientsockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "unable to contact otp_dec_d on given port\n");
        exit(2);
    }

    // Authentication handshake for dec_client
    char auth[] = "dec_bs";   // Must match dec_server's expected auth string
    if (write(clientsockfd, auth, strlen(auth)) < 0) {
        fprintf(stderr, "Client: ERROR writing auth\n");
        exit(1);
    }

    memset(buffer, 0, sizeof(buffer));
    ssize_t n = read(clientsockfd, buffer, sizeof(buffer) - 1);
    if (n < 0) {
        fprintf(stderr, "Client: ERROR reading auth response\n");
        exit(1);
    }
    buffer[n] = '\0';

    // Server must respond with "dec_d_bs" or reject connection
    if (strcmp(buffer, "dec_d_bs") != 0) {
        fprintf(stderr, "unable to contact otp_dec_d on given port\n");
        exit(2);
    }

    int infilelength = get_file_size_from_read(argv[1]);
    int keylength = get_file_size_from_read(argv[2]);

    // Key must be at least as long as ciphertext
    if (keylength < infilelength) {
        fprintf(stderr, "key is too short\n");
        exit(1);
    }

    // Validate ciphertext file characters (only uppercase letters and space allowed)
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR opening file %s\n", argv[1]);
        exit(1);
    }
    char ch;
    while (read(fd, &ch, 1) > 0) {
        if (ch != ' ' && (ch < 'A' || ch > 'Z')) {
            if (ch != '\n') {
                fprintf(stderr, "%s contains invalid characters\n", argv[1]);
                close(fd);
                exit(1);
            }
        }
    }
    close(fd);

    // Send ciphertext file
    sendFile(argv[1], clientsockfd);

    // Send key file
    sendFile(argv[2], clientsockfd);

    // Receive decrypted plaintext from server
    memset(buffer, 0, sizeof(buffer));
    n = read(clientsockfd, buffer, sizeof(buffer) - 1);
    if (n < 0) {
        fprintf(stderr, "Client: ERROR reading from socket\n");
        exit(1);
    }
    buffer[n] = '\0';

    printf("%s", buffer);  // Print exactly what server sent, no extra newline

    close(clientsockfd);
    return 0;
}
