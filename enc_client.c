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

// Call errors and terminate the program
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Calculates the number of bytes of a file
int get_file_size_from_read(const char *filename) {
    int fd = open(filename, O_RDONLY);
    // If filed failed to open, print error
    if (fd < 0) {
        fprintf(stderr, "ERROR opening file %s: %s\n", filename, strerror(errno));
        exit(1);
    }
    // Stores the number of bytes read
    int count = 0;
    // Stores a single character during reading
    char ch;
    // Loops continues read() returns more than 0
    while (read(fd, &ch, 1) > 0) {
        count =+ 1;
    }

    close(fd);
    // Return back the file size
    return count;
}

void sendFile(const char *filename, int sockfd, int filelength) {
    // filename is the file to be sent
    // sockfd is the socket file descriptor used to send data over the network 
    // filelength is the length fo the file 
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "ERROR opening file %s\n", filename);
        exit(1);
    }
    // Temporarily store the contents read from the file
    char buffer[100000];
    int bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read < 0) {
        fprintf(stderr, "Client: ERROR reading file: %s\n", strerror(errno));
        exit(1);
}
    // Track the bytes that have been successfully written 
    int total_written = 0;
    // Loop continues until all the bytes read from the file have been written to the socket
    while (total_written < bytes_read) {
        // Write the bytes from buffer to the socket file descriptor 
        // buffer + total_written is a pointer to the part of the buffer that is not written yet
        // bytes_read - total_written is the number of bytes left to write
        int bytes_written = write(sockfd, buffer + total_written, bytes_read - total_written);
        if (bytes_written < 0) {
            fprintf(stderr, "Client: ERROR writing to socket: %s\n", strerror(errno));
            close(fd);
            exit(1);
        }
        // Update counter for bytes written
        total_written += bytes_written;
    }

    close(fd);
}

int main(int argc, char *argv[]) {
    int clientsockfd, portnum, n;
    // clientsockfd holds file descriptor for the client socket 
    // portnum holds the portnumber to connect to the server
    // n holds the number of bytes read or written
    // Store the server's address information: IP address, Port number, Address family (IPv4)
    struct sockaddr_in server_addr;
    // Holds information IP address
    struct hostent *server;
    char buffer[100000];
    // The server hostname the client will connect to
    const char hostname[] = "localhost";

    // Checks if the program has program name, plaintext input filename, key filename, and port number
    if (argc != 4) {
        fprintf(stderr, "usage %s <inputfile> <key> <port>\n", argv[0]);
        exit(1);
    }

    // Converts the third argument to an integer
    portnum = atoi(argv[3]);
    // Creates a new socket 
    clientsockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (clientsockfd < 0)
        error("Client: ERROR opening socket");
    // Resolve the hostname string into the IP address
    // Used so that the client can connect to the server's IP address
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr, "Client: ERROR, no such host\n");
        exit(2);
    }
    // Clears server_addr
    memset(&server_addr, 0, sizeof(server_addr));
    // Sets the address family to AF_INET
    server_addr.sin_family = AF_INET;
    // Tells the socket which specific server IP to connect to
    memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(portnum);
    // Connect the client socket to the server at the specified IP address and port
    if (connect(clientsockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Client: ERROR connecting to port %d\n", portnum);
        exit(2);
    }

    // Client's authentication code
    char auth[] = "enc_bs"; // Encryption client
    write(clientsockfd, auth, sizeof(auth));
    memset(buffer, 0, sizeof(buffer));
    // Reads the server's response into buffer
    read(clientsockfd, buffer, sizeof(buffer));

    if (strcmp(buffer, "enc_d_bs") != 0) {
        fprintf(stderr, "unable to contact otp_enc_d on given port\n");
        exit(2);
    }

    // Determine the size in bytes of the plaintext file
    int infilelength = get_file_size_from_read(argv[1]);
    // Determine the size in bytes of the key file
    int keylength = get_file_size_from_read(argv[2]);

    // Check if the key is at least as long as the plaintext
    if (keylength < infilelength) {
        fprintf(stderr, "key is too short\n");
        exit(1);
    }

    // Check for valid characters in plaintext
    int plainfd = open(argv[1], O_RDONLY);
    if (plainfd < 0) {
        fprintf(stderr, "ERROR opening file %s\n", argv[1]);
        exit(1);
    }

    // Store one character at a time while reading from the plaintext file
    char ch;
    while (read(plainfd, &ch, 1) > 0) {
        if (ch != ' ' && !(ch >= 'A' && ch <= 'Z')) {
            if (ch != '\n') {
                fprintf(stderr, "%s contains invalid characters\n", argv[1]);
                close(plainfd);
                exit(1);
            }
        }
    }
    close(plainfd);

    // Send plaintext file to the server over the socket
    sendFile(argv[1], clientsockfd, infilelength);

    // Send key file to the server over the socket
    sendFile(argv[2], clientsockfd, keylength);

    // Receive ciphertext
    memset(buffer, 0, sizeof(buffer));
    // Reads the ciphertext result from the server into the buffer
    // Leaves space for the null terminator 
    n = read(clientsockfd, buffer, sizeof(buffer) - 1);
    if (n < 0) {
        perror("Client: ERROR reading from socket");
        exit(1);
    }

    // Displays the encrypted message received from the server to the standard output
    printf("%s\n", buffer);

    close(clientsockfd);
    return 0;
}
