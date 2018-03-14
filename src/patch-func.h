#ifndef PATCH_FUNC_H
# define PATCH_FUNC_H

# include <stdint.h>

# define NBYTES_X86_ABS_JMP64 12
# define NBYTES_X86_REL_JMP32 5

void dump_addr(void *addr, size_t len);

char *x86_build_abs_jmp64(uintptr_t jmp_addr_le);

char *x86_build_rel_jmp32(uintptr_t rip_be, uintptr_t target_addr_be);

void patch_func(uintptr_t old_func_addr, uintptr_t new_func_addr);

#endif /* !PATCH_FUNC_H */
