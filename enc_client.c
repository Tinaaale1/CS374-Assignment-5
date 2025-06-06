#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      
#include <netinet/in.h>

#define MAX_BUFFER 150000

// Print error and exit with code
void error(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// Read file contents, remove newline, validate characters
void grabfilecontents(const char *filename, char *buffer, size_t limit_size) {
    FILE *file = fopen(filename, "r");
    if (!file) error("error", 1);

    if (!fgets(buffer, (int)limit_size, file)) {
        fclose(file);
        error("error", 1);
    }
    fclose(file);

    // Remove newline
    size_t len = strcspn(buffer, "\n");
    buffer[len] = '\0';

    // Validate allowed chars A-Z and space
    static int lettermap[256] = {0};
    if (lettermap['A'] == 0) {
        for (char c = 'A'; c <= 'Z'; c++) lettermap[(unsigned char)c] = 1;
        lettermap[' '] = 1;
    }

    for (size_t i = 0; i < len; i++) {
        if (!lettermap[(unsigned char)buffer[i]]) error("error", 1);
    }
}

// Setup sockaddr_in struct
void netaddressformat(struct sockaddr_in *address, int portNumber, const char *hostname) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent *hostInfo = gethostbyname(hostname);
    if (!hostInfo) error("error", 2);

    memcpy(&address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

// Send all bytes reliably
void sendit(int sockfd, const char *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t sent = send(sockfd, buffer + total, length - total, 0);
        if (sent <= 0) error("error", 2);
        total += sent;
    }
}

// Receive exactly length bytes
void recieveall(int sockfd, char *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t recvd = recv(sockfd, buffer + total, length - total, 0);
        if (recvd <= 0) error("error", 2);
        total += recvd;
    }
}

// Receive string line until '\n'
void receive_line(int sockfd, char *buffer, size_t max_len) {
    size_t i = 0;
    while (i < max_len - 1) {
        char c;
        ssize_t n = recv(sockfd, &c, 1, 0);
        if (n <= 0) error("error", 2);
        if (c == '\n') break;
        buffer[i++] = c;
    }
    buffer[i] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc != 4) error("usage: plaintext key port", 1);

    char gotplaintext[MAX_BUFFER] = {0};
    char gotkey[MAX_BUFFER] = {0};
    char encCptext[MAX_BUFFER] = {0};

    grabfilecontents(argv[1], gotplaintext, sizeof(gotplaintext));
    grabfilecontents(argv[2], gotkey, sizeof(gotkey));

    int pt_len = (int)strlen(gotplaintext);
    int key_len = (int)strlen(gotkey);
    if (key_len < pt_len) error("error", 1);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("error", 2);

    struct sockaddr_in server_addr;
    netaddressformat(&server_addr, atoi(argv[3]), "localhost");

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        dprintf(STDERR_FILENO, "error\n");
        exit(2);
    }

    // Step 1: Send client ID
    sendit(sockfd, "enc_client", strlen("enc_client"));

    // Step 2: Receive accept/reject
    char response[20];
    memset(response, 0, sizeof(response));
    ssize_t recvd = recv(sockfd, response, sizeof(response) - 1, 0);
    if (recvd <= 0) error("error", 2);
    response[recvd] = '\0';

    if (strcmp(response, "accept") != 0) error("error", 2);

    // Step 3: Send plaintext size as ASCII string with newline
    char size_str[20];
    snprintf(size_str, sizeof(size_str), "%d\n", pt_len);
    sendit(sockfd, size_str, strlen(size_str));

    // Step 4: Receive acknowledgment "size_received"
    receive_line(sockfd, response, sizeof(response));
    if (strcmp(response, "size_received") != 0) error("error", 2);

    // Step 5: Send plaintext bytes
    sendit(sockfd, gotplaintext, pt_len);

    // Step 6: Receive acknowledgment "size_received"
    receive_line(sockfd, response, sizeof(response));
    if (strcmp(response, "size_received") != 0) error("error", 2);

    // Step 7: Send key size as ASCII string with newline
    snprintf(size_str, sizeof(size_str), "%d\n", key_len);
    sendit(sockfd, size_str, strlen(size_str));

    // Step 8: Receive acknowledgment "size_received"
    receive_line(sockfd, response, sizeof(response));
    if (strcmp(response, "size_received") != 0) error("error", 2);

    // Step 9: Send key bytes
    sendit(sockfd, gotkey, key_len);

    // Step 10: Receive ciphertext bytes (length = pt_len)
    recieveall(sockfd, encCptext, pt_len);

    // Print ciphertext + newline
    write(STDOUT_FILENO, encCptext, pt_len);
    write(STDOUT_FILENO, "\n", 1);

    close(sockfd);
    return 0;
}
