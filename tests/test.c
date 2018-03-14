#include <stdio.h>

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
    printf("toto\n");
    foo(3);
    return 0;
}
