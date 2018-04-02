#include <stdio.h>

void foo(void)
{
    printf("I'm actually doing nothing usefull %d\n", 0);
}

int main(void)
{
    while (1)
        foo();
}
