#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// argc is the number of command-line arguments 
// argv is an array of strings of the command-line arguments
int main(int argc, char* argv[]) {
    // First argument is the program name 
    // Second argument is the key length 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }
    // Convert the second command-line argument and store it in length 
    int length = atoi(argv[1]);
    // If length is 0 or negative then error 
    if (length <= 0) {
        fprintf(stderr, "Error: key length must be a positive integer\n");
        return 1;
    }
    // Random numbre generator with teh current time 
    srand(time(NULL));

    int i;
    for (i = 0; i < length; i++) {
        int r = rand() % 27;
        if (r == 26) {
            printf(" ");
        } else {
            printf("%c", 'A' + r);
        }
    }

    printf("\n");
    return 0;
}
