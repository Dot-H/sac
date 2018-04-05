#include <stdint.h>
#include <stdlib.h>

/**
** \brief This function is used to be compiled and injected into a traced
** process in order to make it dlopen a specified path.
** All arguments must be set-up by in the regs by the injecter following
** the linux convention.
*
** The @lib_pathsize argument must include a terminating nullbyte in the count
**
** The int $3 are here to give back control to the injector. The first one
** should be use to check the return value of malloc and memcpy the path of the
** lib in it. The second one should be to restore the tracee's registers and
** code.
**
** Note that the registers are supposed to be restored after this payload
*/
void open_shared_library(size_t lib_pathsize, uintptr_t dlopen_addr,
                        uintptr_t malloc_addr, uintptr_t free_addr)
{
    /* save dlopen_addr */
    asm volatile (
            "push %r10\n\t"
            "push %rsi\n\t"
            );

    /* Call malloc */
    asm volatile (
            "callq *%rdx\n\t" // Call malloc_addr
            "int $3\n\t" // Let injector setup the allocated buf in rax
            );

    /* Call __libc_dlopen_mode */
    asm volatile (
            "pop %r9\n\t" // Prepare jump to __libc_dlopen_mode
            "push %rax\n\t" // Save malloc's address
            "mov %rax, %rdi\n\t" // Put the return value of malloc
            "xor %rsi, %rsi\n\t"
            "inc %rsi\n\t"
//            "movabs $1, %rsi\n\t" // Put RLTD_LAZY flag
            "callq *%r9\n\t" // Call __libc_dlopen_mode
            );

    /* .
    ** Shorter than mov $1, %rsp
    */
    asm volatile (
            "pop %rdi\n\t" // Get back the address of the allocated buffer
            "pop %r9\n\t" // Prepare jump to free
            "push %rax\n\t"
            "callq *%r9\n\t" // call free
            "pop %rax\n\t"
            );

    /* interrupt the process to let the injecter read the return
    ** value and clear the registers / memory space
    */
    asm volatile (
            "int $3\n\t"
            );

    // Do not need a leave since the registers will be reset
}

void close_shared_library(uintptr_t handle, uintptr_t dlclose_addr)
{
    /* We suppose that handle is in %rdi */
    asm volatile (
            "callq *%rsi\n\t" // Call __libc_dlclose
            );

    /* interrupt the process to let the injecter read the return
    ** value and clear the registers / memory space
    */
    asm volatile (
            "int $3\n\t"
            );

    // Do not need a leave since the registers will be reset
}
