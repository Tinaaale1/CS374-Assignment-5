#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char listofchars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ ";

int main(int argc, char *argv[]) {
    if (argc != 2) {
        write(2, "Usage: ", 7);
        write(2, argv[0], strlen(argv[0]));
        write(2, " keylength\n", 11);
        exit(1);
    }

    char *endptr;
    long key_length = strtol(argv[1], &endptr, 10);
    if (*endptr != '\0' || key_length <= 0) {
        write(2, "Error: Key length must be a positive integer\n", 44);
        exit(1);
    }

    srand((unsigned int)time(NULL));

    for (long i = 0; i < key_length; i++) {
        char c = listofchars[rand() % 27];
        write(1, &c, 1);
    }

    char newline = '\n';
    write(1, &newline, 1);

    return 0;
}
