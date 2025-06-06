#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>  
#include <sys/socket.h> 
#include <netdb.h>      
#include <netinet/in.h>

#define MAX_BUFFER 150000

// Error helper: print message and exit with code
void error(const char *msg, int code) {
    fprintf(stderr, "%s\n", msg);
    exit(code);
}

// Read file contents into buffer, validate chars (A-Z and space), remove newline
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

    // Validate characters
    static int lettermap[256] = {0};
    if (lettermap['A'] == 0) {
        for (char c = 'A'; c <= 'Z'; c++) lettermap[(unsigned char)c] = 1;
        lettermap[' '] = 1;
    }

    for (size_t i = 0; i < len; i++) {
        if (!lettermap[(unsigned char)buffer[i]]) error("error", 1);
    }
}

// Prepare sockaddr_in struct with given hostname and port
void netaddressformat(struct sockaddr_in *address, int portNumber, const char *hostname) {
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_port = htons(portNumber);

    struct hostent *hostInfo = gethostbyname(hostname);
    if (!hostInfo) error("ERROR", 2);

    memcpy(&address->sin_addr.s_addr, hostInfo->h_addr_list[0], hostInfo->h_length);
}

// Wrapper to send all bytes
void sendit(int sockfd, const char *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t sent = send(sockfd, buffer + total, length - total, 0);
        if (sent <= 0) error("error", 2);
        total += sent;
    }
}

// Wrapper to receive all bytes
void recieveall(int sockfd, char *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        ssize_t recvd = recv(sockfd, buffer + total, length - total, 0);
        if (recvd <= 0) error("error", 2);
        total += recvd;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 4) error("usage: plaintext key port", 1);

    char gotplaintext[MAX_BUFFER] = {0};
    char gotkey[MAX_BUFFER] = {0};
    char encCptext[MAX_BUFFER] = {0};

    grabfilecontents(argv[1], gotplaintext, sizeof(gotplaintext));
    grabfilecontents(argv[2], gotkey, sizeof(gotkey));

    int calcptbites = (int)strlen(gotplaintext);
    int keybits = (int)strlen(gotkey);
    if (keybits < calcptbites) error("error", 1);

    int coresocket = socket(AF_INET, SOCK_STREAM, 0);
    if (coresocket < 0) error("error", 2);

    struct sockaddr_in srvNetInfo;
    netaddressformat(&srvNetInfo, atoi(argv[3]), "localhost");

    if (connect(coresocket, (struct sockaddr *)&srvNetInfo, sizeof(srvNetInfo)) < 0) {
        dprintf(STDERR_FILENO, "ERROR %s\n", argv[3]);
        exit(2);
    }

    // Send "ENC"
    sendit(coresocket, "ENC", 3);

    // Receive "OK"
    char response[2];
    recieveall(coresocket, response, 2);
    if (strncmp(response, "OK", 2) != 0) error("error", 2);

    // Send plaintext size, then plaintext
    sendit(coresocket, (char *)&calcptbites, sizeof(int));
    sendit(coresocket, gotplaintext, calcptbites);

    // Send key size, then key
    sendit(coresocket, (char *)&keybits, sizeof(int));
    sendit(coresocket, gotkey, keybits);

    // Receive encrypted text size (overwrite calcptbites, unused in your original code but consistent)
    recieveall(coresocket, (char *)&calcptbites, sizeof(int));

    // Receive encrypted text
    recieveall(coresocket, encCptext, calcptbites);

    // Print encrypted message + newline
    write(STDOUT_FILENO, encCptext, (size_t)calcptbites);
    write(STDOUT_FILENO, "\n", 1);

    close(coresocket);
    return 0;
}
