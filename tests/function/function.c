#include <stdio.h>

void foo(void)
{
    printf("I'm actually doing nothing usefull %d\n", 0);
    printf("But now yes!\n");
    printf("Or yes..\n");
}

int main(void)
{
    while (1)
        foo();
}
