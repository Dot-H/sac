#include <stdio.h>

int toto = 5;

void print_toto(void) {
    printf("addr: 0x%lx, value: %d\n", &toto, toto);
//    toto += 1;
}

int main(int argc, char* argv[])
{
    while (1) {
        print_toto();
    }
}
//t
//t
