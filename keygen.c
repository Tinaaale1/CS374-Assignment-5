#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>

// Total number of allowed characters: A-Z (0-25) and space (26)
#define ALPHABET_SIZE 27

// Get a random character from the allowed set
char getRandomChar() {
    int r = rand() % ALPHABET_SIZE;
    return (r == 26) ? ' ' : 'A' + r;
}

int main(int argc, char *argv[]) {
    // Check for correct number of arguments
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        exit(1);
    }

    // Parse keylength argument
    char *endptr;
    long keyLength = strtol(argv[1], &endptr, 10);

    // Error checking for strtol
    if (*endptr != '\0' || keyLength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer\n");
        exit(1);
    }

    // Seed the random number generator
    srand((unsigned int) time(NULL));

    // Generate and print key
    for (long i = 0; i < keyLength; ++i) {
        char c = getRandomChar();
        printf("%c", c);
    }

    // Append newline at the end
    printf("\n");

    return 0;
}
