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

void setupAddressStruct(struct sockaddr_in* address, int portNumber, char* hostname){
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

int readFile(const char* filename, char* buffer) {
    FILE* f = fopen(filename, "r");
    if (!f) return 0;
    size_t n = fread(buffer, 1, MAX_BUFFER - 1, f);
    buffer[n] = '\0';
    fclose(f);
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';
    return 1;
}

int validateText(const char* text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (text[i] != ' ' && (text[i] < 'A' || text[i] > 'Z')) {
            return 0;
        }
    }
    return 1;
}

ssize_t sendAll(int socketFD, const char* buffer, size_t length) {
    size_t totalSent = 0;
    while (totalSent < length) {
        ssize_t sent = send(socketFD, buffer + totalSent, length - totalSent, 0);
        if (sent < 0) return -1;
        totalSent += sent;
    }
    return totalSent;
}

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
        fprintf(stderr,"USAGE: %s ciphertext key port\n", argv[0]); 
        exit(1); 
    } 

    char ciphertext[MAX_BUFFER];
    char key[MAX_BUFFER];
    char buffer[MAX_BUFFER];
    int portNumber = atoi(argv[3]);
    if (portNumber <= 0) {
        fprintf(stderr, "dec_client: ERROR invalid port\n");
        exit(1);
    }

    // Read ciphertext file
    if (!readFile(argv[1], ciphertext)) {
        fprintf(stderr, "dec_client: ERROR opening ciphertext file %s\n", argv[1]);
        exit(1);
    }

    // Read key file
    if (!readFile(argv[2], key)) {
        fprintf(stderr, "dec_client: ERROR opening key file %s\n", argv[2]);
        exit(1);
    }

    // Validate ciphertext and key characters
    if (!validateText(ciphertext)) {
        fprintf(stderr, "dec_client: ERROR ciphertext contains bad characters\n");
        exit(1);
    }
    if (!validateText(key)) {
        fprintf(stderr, "dec_client: ERROR key contains bad characters\n");
        exit(1);
    }

    // Check key length >= ciphertext length
    if (strlen(key) < strlen(ciphertext)) {
        fprintf(stderr, "dec_client: ERROR key is too short\n");
        exit(1);
    }

    // Create socket
    int socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (socketFD < 0) {
        fprintf(stderr, "dec_client: ERROR opening socket\n");
        exit(2);
    }

    struct sockaddr_in serverAddress;
    setupAddressStruct(&serverAddress, portNumber, "localhost");

    // Connect to server
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        fprintf(stderr, "dec_client: ERROR connecting to port %d\n", portNumber);
        close(socketFD);
        exit(2);
    }

    // Send handshake to identify as dec_client
    snprintf(buffer, sizeof(buffer), "DEC_CLIENT\n");
    if (sendAll(socketFD, buffer, strlen(buffer)) < 0) {
        fprintf(stderr, "dec_client: ERROR sending handshake\n");
        close(socketFD);
        exit(2);
    }

    // Receive handshake response
    if (!recvUntilNewline(socketFD, buffer, sizeof(buffer))) {
        fprintf(stderr, "dec_client: ERROR no handshake response\n");
        close(socketFD);
        exit(2);
    }

    // Reject if not dec_server
    if (strcmp(buffer, "DEC_SERVER") == 0) {
        // Proceed normally
    } else if (strcmp(buffer, "ENC_SERVER") == 0) {
        fprintf(stderr, "dec_client: ERROR rejected by server (likely enc_server)\n");
        close(socketFD);
        exit(2);
    } else {
        fprintf(stderr, "dec_client: ERROR unknown server response\n");
        close(socketFD);
        exit(2);
    }

    // Send ciphertext + newline
    snprintf(buffer, sizeof(buffer), "%s\n", ciphertext);
    if (sendAll(socketFD, buffer, strlen(buffer)) < 0) {
        fprintf(stderr, "dec_client: ERROR sending ciphertext\n");
        close(socketFD);
        exit(2);
    }

    // Send key + newline
    snprintf(buffer, sizeof(buffer), "%s\n", key);
    if (sendAll(socketFD, buffer, strlen(buffer)) < 0) {
        fprintf(stderr, "dec_client: ERROR sending key\n");
        close(socketFD);
        exit(2);
    }

    // Receive plaintext until newline
    if (!recvUntilNewline(socketFD, buffer, sizeof(buffer))) {
        fprintf(stderr, "dec_client: ERROR receiving plaintext\n");
        close(socketFD);
        exit(2);
    }

    // Output plaintext to stdout
    printf("%s\n", buffer);

    close(socketFD);
    return 0;
}
