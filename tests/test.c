#include <stdio.h>

int toto = 0;
static int tata = 3;

static inline void empty(void)
{
}

int toto_cnt(void)
{
    static int cnt = 0;
    cnt += 1;
    return cnt;
}

int foo(int arg)
{
    int ret = 1 + 34 + arg;
    printf("toto va plus a la plage %d fois\n", toto_cnt());
    tata += 1;
    return ret;
}
