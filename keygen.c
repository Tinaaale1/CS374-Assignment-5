#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Function to check command-line argument count
void check_args(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(EXIT_FAILURE);
    }
}

// argc is the number of command-line arguments 
// argv is an array of strings of the command-line arguments
int main(int argc, char* argv[]) {
    // First argument is the program name 
    // Second argument is the key length 
    check_args(argc, argv);

    // Convert the second command-line argument and store it in length 
    int length = atoi(argv[1]);
    // If length is 0 or negative then error 
    if (length <= 0) {
        fprintf(stderr, "Error: key length must be a positive integer\n");
        return 1;
    }

    // Allocate space for the key (+1 for null terminator)
    char key[length + 1];

    // Random number generator with teh current time 
    srand(time(NULL));

    // Fill the key with random characters from A-Z and space
    for (int i = 0; i < length; i++) {
        int r = rand() % 27;
        if (r == 26) {
            key[i] = ' ';
        } else {
            key[i] = 'A' + r;
        }
    }

    key[length] = '\0'; // Null-terminate the key string

    printf("%s\n", key);

    return 0;
}
