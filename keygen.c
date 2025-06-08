#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[]) {
    // Checks whether exactly one argument, program name was provided 
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }
    // Converts the input string to an integer and store it in keyLength
    int keyLength = atoi(argv[1]);
    if (keyLength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer.\n");
        return 1;
    }
    // Initializes the random number generator used by rand()
    srand((unsigned int)time(NULL));
    // The characters in the file generated will be any of the 27 allowed characters
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    // Total number of bytes in the array and null terminator 
    int charsetSize = sizeof(charset) - 1; 

    for (int i = 0; i < keyLength; i++) {
        int index = rand() % charsetSize;
        // Prints a single character from the the charset array at the randomly selected index
        printf("%c", charset[index]);

    }
    printf("\n");
    return 0;
}
