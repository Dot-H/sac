#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "build.h"
#include "patch-func.h"

int foo(int arg)
{
    return arg;
}

int main(int argc, char *argv[])
{
    if (argc < 2)
        return 1;

    if (build(argv[1]) != 0)
        fprintf(stderr, "Build failed\n");

    printf("foo before load: %d\n", foo(0));

    void *handle = dlopen("/home/doth/EPITA/lse/sac/build/test.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "%d, %s\n", __LINE__, dlerror());
        exit(EXIT_FAILURE);
    }

    dlerror();

    /* From dlopen manpage:
    According to the ISO C standard, casting between function
    pointers and 'void *', as done above, produces undefined results.
    POSIX.1-2003 and POSIX.1-2008 accepted this state of affairs and
    proposed the following workaround:

      *(void **) (&cosine) = dlsym(handle, "cos");

    This (clumsy) cast conforms with the ISO C standard and will
    avoid any compiler warnings.

    The 2013 Technical Corrigendum to POSIX.1-2008 (a.k.a.
    POSIX.1-2013) improved matters by requiring that conforming
    implementations support casting 'void *' to a function pointer.
    Nevertheless, some compilers (e.g., cc with the '-pedantic'
    option) may complain about the cast used in this program. */

    void *addr = dlsym(handle, "foo");
    const char *error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "%d, %s\n", __LINE__, dlerror());
        exit(EXIT_FAILURE);
    }


    patch_func((uintptr_t)foo, (uintptr_t)addr);
    printf("foo: %d\n", foo(0));

    return 0;
}
