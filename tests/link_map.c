#include <stdio.h>
#include <link.h>

int main(void)
{
    printf("%p\n", (void *)&_r_debug);
    return 0;
}
