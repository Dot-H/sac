#include <stdio.h>

int toto = 0;
static int tata = 3;

static inline void empty(void)
{
}

int foo(int arg)
{
    int ret = 1 + 34 + arg;
    return ret;
}

int main(void)
{
    empty();
    foo(3);
    tata = 4;
    return 0;
}
