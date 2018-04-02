#include <stdio.h>

int toto = 0;
static int tata = 3;

static inline void empty(void)
{
}

int foo(int arg)
{
    int ret = 1 + 34 + arg;
    printf("toto va a la plage\n");
    tata += 1;
    return ret;
}
