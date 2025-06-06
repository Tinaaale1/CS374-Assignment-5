#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      
#include <netinet/in.h>

#define MAX_BUFFER 150000

void error_exit(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// Sends all bytes in buffer over sockfd
void sendit(int sockfd, const char *buffer, size_t len) {
    size_t total_sent = 0;
    while (total_sent < len) {
        ssize_t sent = send(sockfd, buffer + total_sent, len - total_sent, 0);
        if (sent < 0) {
            perror("send");
            exit(2);
        }
        total_sent += sent;
    }
}

// Receives exactly len bytes from sockfd into buffer
void recieveall(int sockfd, char *buffer, size_t len) {
    size_t total_recv = 0;
    while (total_recv < len) {
        ssize_t recvd = recv(sockfd, buffer + total_recv, len - total_recv, 0);
        if (recvd < 0) {
            perror("recv");
            exit(2);
        }
        if (recvd == 0) {
            fprintf(stderr, "Connection closed prematurely\n");
            exit(2);
        }
        total_recv += recvd;
    }
}

// Simplified grabfilecontents: read file into payload buffer, validate chars
void grabfilecontents(const char *filename, char *payload, int limit_size) {
    FILE *file = fopen(filename, "r");
    if (!file) error_exit("error", 1);

    if (payload) {
        if (!fgets(payload, limit_size, file)) {
            fclose(file);
            error_exit("error", 1);
        }
    }
    fclose(file);

    // Remove trailing newline if any
    size_t len = strcspn(payload, "\n");
    payload[len] = '\0';

    // Validate characters: A-Z or space only
    for (size_t i = 0; i < strlen(payload); i++) {
        if (!((payload[i] >= 'A' && payload[i] <= 'Z') || payload[i] == ' ')) {
            error_exit("error", 1);
        }
    }
}

// Setup sockaddr_in struct with zeroed memory, port, and hostname
void netaddressformat(struct sockaddr_in *address, int portNumber, const char *hostname) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent *hostInfo = gethostbyname(hostname);
    if (!hostInfo) error_exit("ERROR", 2);

    memcpy(&address->sin_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

int main(int argc, char *argv[]) {
    if (argc < 4) error_exit("USAGE", 1);

    char ciphertext[MAX_BUFFER] = {0};
    char key[MAX_BUFFER] = {0};
    char plaintext[MAX_BUFFER] = {0};

    grabfilecontents(argv[1], ciphertext, sizeof(ciphertext));
    grabfilecontents(argv[2], key, sizeof(key));

    int ciphertext_len = strlen(ciphertext);
    int key_len = strlen(key);

    if (key_len < ciphertext_len) error_exit("ERROR", 1);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error_exit("ERROR", 2);

    struct sockaddr_in server_address;
    netaddressformat(&server_address, atoi(argv[3]), "localhost");

    if (connect(sockfd, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
        fprintf(stderr, "ERROR %s\n", argv[3]);
        exit(2);
    }

    // Send "DEC" to server
    sendit(sockfd, "DEC", 3);

    memset(plaintext, 0, sizeof(plaintext));
    // Receive server's OK confirmation
    recieveall(sockfd, plaintext, 2);

    if (strcmp(plaintext, "OK") != 0) error_exit("ERROR", 2);

    // Send ciphertext length
    sendit(sockfd, (char *)&ciphertext_len, sizeof(int));

    // Send ciphertext data
    if (ciphertext_len > 0) sendit(sockfd, ciphertext, ciphertext_len);

    // Send key length
    sendit(sockfd, (char *)&key_len, sizeof(int));

    // Send key data
    if (key_len > 0) sendit(sockfd, key, key_len);

    // Receive decrypted message length
    recieveall(sockfd, (char *)&ciphertext_len, sizeof(int));

    memset(plaintext, 0, sizeof(plaintext));
    if (ciphertext_len > 0) recieveall(sockfd, plaintext, ciphertext_len);

    printf("%s\n", plaintext);

    close(sockfd);

    return 0;
}
