#include <stdio.h>
#include <stdlib.h>
#include <time.h>

void usage(int argc, char *argv[]){
    if (argc != 2){ 
        fprintf(stderr, "Usage: %s length\n", argv[0]); 
        exit(1);
    }
}

int main(int argc, char *argv[]){
    usage(argc, argv);

    int length = atoi(argv[1]);
    if (length <= 0) {
        fprintf(stderr, "Error: key length must be positive integer\n");
        exit(1);
    }

    char key[length + 1];  // Now length is known

    srand(time(NULL));

    for (int i = 0; i < length; i++){
        key[i] = " ABCDEFGHIJKLMNOPQRSTUVWXYZ"[rand() % 27];
    }
    key[length] = '\0';

    printf("%s\n", key);  // outputs the key plus a newline

    return 0;
}
