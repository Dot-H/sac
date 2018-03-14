#include <stdio.h>
#include <stdlib.h>

#include "patch-func.h"

void dump_addr(void *addr, size_t len)
{
    char *dump = (char *)addr;
    for (size_t i = 0; i < len; ++i)
        printf("%x", dump[i] & 0xFF);
}

char *x86_build_abs_jmp64(uintptr_t jmp_addr_le)
{
    char *jmp_payload = malloc(NBYTES_X86_ABS_JMP64 + 1);

    sprintf(jmp_payload, "\x48\xb8%8s\xff\xe0", (char *)&jmp_addr_le);
    dump_addr(jmp_payload, NBYTES_X86_ABS_JMP64);
    
    return jmp_payload;
}

char *x86_build_rel_jmp32(uintptr_t rip_be, uintptr_t target_addr_be)
{
    char *jmp_payload = malloc(NBYTES_X86_REL_JMP32 + 1);

    int32_t jmp_len = target_addr_be - (rip_be + NBYTES_X86_REL_JMP32);
    sprintf(jmp_payload, "\xe9%4s", (char *)&jmp_len);
    dump_addr(jmp_payload, NBYTES_X86_REL_JMP32);

    return jmp_payload;
}

void patch_func(uintptr_t old_func_addr_be, uintptr_t new_func_addr_be)
{
    intptr_t size_jmp = new_func_addr_be - old_func_addr_be; 
    size_jmp = (size_jmp > 0) ? -size_jmp : size_jmp;
    char *patch = NULL;
    if (size_jmp > INT32_MAX)
        patch = x86_build_abs_jmp64(new_func_addr_be);
    else
        patch = x86_build_rel_jmp32(old_func_addr_be, new_func_addr_be);

    (void)patch;
}
