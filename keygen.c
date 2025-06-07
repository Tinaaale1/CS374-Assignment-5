#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/**
 * @brief Generates a random key composed of uppercase letters and spaces.
 *
 * The key length is provided as a command line argument.
 * Outputs the generated key followed by a newline to stdout.
 *
 * @param argc Number of command line arguments.
 * @param argv Command line arguments array.
 * @return 0 on success, 1 on error.
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }

    int keyLength = atoi(argv[1]);
    if (keyLength <= 0) {
        fprintf(stderr, "Error: keylength must be a positive integer.\n");
        return 1;
    }

    // Seed the random number generator once
    srand((unsigned int)time(NULL));

    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";
    int charsetSize = sizeof(charset) - 1; // exclude null terminator

    for (int i = 0; i < keyLength; i++) {
        int index = rand() % charsetSize;
        putchar(charset[index]);
    }
    putchar('\n');

    return 0;
}
