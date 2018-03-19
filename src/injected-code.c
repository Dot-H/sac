#include <stdint.h>
#include <stdlib.h>

/**
** \brief This function is used to be compiled injected into a traced
** process in order to make it dlopen a specified path.
** Both arguments must be set-up by in the regs by the injecter in
** order to create the buffer which will contains the absolute path to
** the shared library.
** Note that the path must be 'memset' by the injecter since it is not
** in the tracee's memory space. In order to do that, the function
** will send a SIGSTOP through a int 3 after the allocation on the stack.
** When contuining, the function supposes that the buffer is correctly filled.
** Once done, the function stores the result to %eax and SIGSTOP.
** The injecter must then restore the registers and reset the memory space.
*/
int open_shared_library(uintptr_t dlopen_addr, size_t path_size)
{
    /* Allocate buffer of path_size and Let the injecter
    ** setup the path in %rsp
    */
    asm volatile (
            "sub %rsi, %rsp\n\t"
            "int $3\n\t" // 
            );

    /* Prepare the register to jump and put the buffer
    ** as first argument
    */
    asm volatile (
            "mov %rdi, %r9\n\t"
            "mov %rsp, %rdi\n\t"
            );

    /* Put RLTD_LAZY flag as second argument.
    ** Shorter than mov $1, %rsp
    */
    asm volatile (
            "xor %rsi, %rsi\n\t"
            "inc %rsi\n\t"
            );


    /* Call dlopen_addr and interrupt the process to let
    ** the injecter read the return value and clear the
    ** registers / memory space
    */
    asm volatile (
            "callq *%r9\n\t"
            "int $3\n\t"
            );

    // Do not need a leave since the registers will be reset
    // Find compiler builtin to suppress the default retq
}
