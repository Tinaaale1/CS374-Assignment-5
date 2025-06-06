#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      
#include <netinet/in.h>

#define MAX_BUFFER 150000

// Error function: print to stderr and exit with code 1 or 2 depending on context
void error_exit(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// Set up the address struct
void setupAddressStruct(struct sockaddr_in* address, 
                        int portNumber, 
                        char* hostname){
    memset((char*) address, '\0', sizeof(*address)); 
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent* hostInfo = gethostbyname(hostname); 
    if (hostInfo == NULL) { 
        fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
        exit(2); 
    }
    memcpy((char*) &address->sin_addr.s_addr, 
           hostInfo->h_addr_list[0],
           hostInfo->h_length);
}

// Read entire file into buffer, removing trailing newline if present
int readFile(const char* filename, char* buffer) {
    FILE* f = fopen(filename, "r");
    if (!f) return 0;
    size_t n = fread(buffer, 1, MAX_BUFFER - 1, f);
    buffer[n] = '\0';
    fclose(f);
    // Remove trailing newline if present
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
    return 1;
}

// Validate that the text contains only A-Z and space
int validateText(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && (text[i] < 'A' || text[i] > 'Z')) {
            return 0;
        }
    }
    return 1;
}

// Send all bytes reliably
ssize_t sendAll(int socketFD, const char* buffer, size_t length) {
    size_t totalSent = 0;
    while (totalSent < length) {
        ssize_t sent = send(socketFD, buffer + totalSent, length - totalSent, 0);
        if (sent < 0) return -1;
        totalSent += sent;
    }
    return totalSent;
}

// Receive data until newline, store into buffer (null-terminated)
int recvUntilNewline(int socketFD, char* buffer, size_t maxLen) {
    size_t total = 0;
    while (total < maxLen - 1) {
        char ch;
        ssize_t r = recv(socketFD, &ch, 1, 0);
        if (r <= 0) return 0; // error or disconnect
        if (ch == '\n') {
            buffer[total] = '\0';
            return 1;
        }
        buffer[total++] = ch;
    }
    buffer[maxLen - 1] = '\0';
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 4) { 
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]); 
        exit(1); 
    } 

    char plaintext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char buffer[MAX_BUFFER];
    int portNumber = atoi(argv[3]);
    if (portNumber <= 0) {
        fprintf(stderr, "enc_client: ERROR invalid port\n");
        exit(1);
    }

    // Read plaintext file
    if (!readFile(argv[1], plaintext)) {
        fprintf(stderr, "enc_client: ERROR opening plaintext file %s\n", argv[1]);
        exit(1);
    }

    // Read key file
    if (!readFile(argv[2], key)) {
        fprintf(stderr, "enc_client: ERROR opening key file %s\n", argv[2]);
        exit(1);
    }

    // Validate plaintext and key characters
    if (!validateText(plaintext)) {
        fprintf(stderr, "enc_client: ERROR plaintext contains bad characters\n");
        exit(1);
    }
    if (!validateText(key)) {
        fprintf(stderr, "enc_client: ERROR key contains bad characters\n");
        exit(1);
    }

    // Check key length >= plaintext length
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "enc_client: ERROR key is too short\n");
        exit(1);
    }

    // Create socket
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        fprintf(stderr, "enc_client: ERROR opening socket\n");
        exit(2);
    }

    struct sockaddr_in serverAddress;
    setupAddressStruct(&serverAddress, portNumber, "localhost");

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        fprintf(stderr, "enc_client: ERROR connecting to port %d\n", portNumber);
        close(socketFD);
        exit(2);
    }

    // Send handshake to identify as enc_client
    snprintf(buffer, sizeof(buffer), "ENC_CLIENT\n");
    if (sendAll(socketFD, buffer, strlen(buffer)) < 0) {
        fprintf(stderr, "enc_client: ERROR sending handshake\n");
        close(socketFD);
        exit(2);
    }

    // Receive handshake response
    if (!recvUntilNewline(socketFD, buffer, sizeof(buffer))) {
        fprintf(stderr, "enc_client: ERROR no handshake response\n");
        close(socketFD);
        exit(2);
    }

    // Reject if not enc_server
    if (strcmp(buffer, "ENC_SERVER") != 0) {
        fprintf(stderr, "enc_client: ERROR rejected by server (likely dec_server)\n");
        close(socketFD);
        exit(2);
    }

    // Prepare and send plaintext + newline safely
    size_t len = strlen(plaintext);
    if (len + 1 >= sizeof(buffer)) {
        fprintf(stderr, "enc_client: ERROR plaintext too large\n");
        close(socketFD);
        exit(1);
    }
    memcpy(buffer, plaintext, len);
    buffer[len] = '\n';
    buffer[len + 1] = '\0';

    if (sendAll(socketFD, buffer, len + 1) < 0) {
        fprintf(stderr, "enc_client: ERROR sending plaintext\n");
        close(socketFD);
        exit(2);
    }

    // Prepare and send key + newline safely
    len = strlen(key);
    if (len + 1 >= sizeof(buffer)) {
        fprintf(stderr, "enc_client: ERROR key too large\n");
        close(socketFD);
        exit(1);
    }
    memcpy(buffer, key, len);
    buffer[len] = '\n';
    buffer[len + 1] = '\0';

    if (sendAll(socketFD, buffer, len + 1) < 0) {
        fprintf(stderr, "enc_client: ERROR sending key\n");
        close(socketFD);
        exit(2);
    }

    // Receive ciphertext until newline
    if (!recvUntilNewline(socketFD, buffer, sizeof(buffer))) {
        fprintf(stderr, "enc_client: ERROR receiving ciphertext\n");
        close(socketFD);
        exit(2);
    }

    // Output ciphertext to stdout
    printf("%s\n", buffer);

    close(socketFD);
    return 0;
}
