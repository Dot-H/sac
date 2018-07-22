#include <stdio.h>
#include "b.h"

int main(void) {
    do {
        char buf[1];
        toto();
        printf("Press a key to continue\n");
    } while (fread(buf, 1, 1, stdin) > 0 && buf[0] != EOF);

    return 0;
}
