#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <err.h>
#include <stdint.h>

typedef int (* mprotect_f) (uintptr_t, uintptr_t, uintptr_t);

int test_write_remove(void *handle) {
    mprotect_f rm_write_protect = dlsym(handle, "rm_write_protect");
    const char *dlerr;
    if ((dlerr = dlerror())) {
      fprintf(stderr, "%s\n", dlerr);
      return -1;
    }

    void *maddr = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (maddr == MAP_FAILED)
        err(1, "");

    *(char*)maddr = 1;
    rm_write_protect((uintptr_t)maddr, 4096, (uintptr_t)&mprotect);
    *((char*)maddr + 234) = 2; //Testing the write protection. Should segv

    munmap(maddr, 4096);

    return 0;
}

int test_write_add(void *handle) {
    mprotect_f add_write_protect = dlsym(handle, "add_write_protect");
    const char *dlerr;
    if ((dlerr = dlerror())) {
        fprintf(stderr, "%s\n", dlerr);
        return -1;
    }

    void *maddr = mmap(NULL, 4096, PROT_READ,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (maddr == MAP_FAILED)
        err(1, "");

    add_write_protect((uintptr_t)maddr, 4096, (uintptr_t)&mprotect);
    *(char*)maddr = 2; //Testing the write protection. Should not segv

    munmap(maddr, 4096);

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_shared>\n", argv[0]);
        return 1;
    }

    void *handle = dlopen(argv[1], RTLD_NOW);
    const char *dlerr;
    if ((dlerr = dlerror())) {
        fprintf(stderr, "%s\n", dlerr);
        return 1;
    }

    if (test_write_add(handle) == -1)
        return 1;

    if (test_write_remove(handle) == -1)
        return 1;
}
