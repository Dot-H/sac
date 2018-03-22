#include <stdio.h>
#include <link.h>

int main(void)
{
    printf("%p\n", (void *)&_r_debug);
    printf("%p\n", (void *)_r_debug.r_map);

    
    struct link_map *head = _r_debug.r_map;
    for (struct link_map *tmp = head; tmp; tmp = tmp->l_next)
    {
        printf("0x%lx\n", tmp->l_addr);
        printf("%p\n", (void *)tmp->l_name);
    }

    return 0;
}
