#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "build.h"

#define TST_FILE_PATH "../tests/test.c"
#define OPT_KEEP_OBJECT 1

const char *compile_command(const char *filename)
{
    (void)filename;
    // fPic is not needed on current versions of arch
    return "gcc -Wall -Wextra -Werror -std=c99 -pedantic "
           "-fPIC -o test.o -c "TST_FILE_PATH;
}

const char *link_command(const char *filename)
{
    (void)filename;
    return "gcc test.o -shared -o test.so";
}

char *build_full_command(const char *cpl_cmd, const char *lnk_cmd)
{
    char *ret = malloc(strlen(cpl_cmd) + SH_AND_LEN + strlen(lnk_cmd));
    if (!ret)
        return NULL;

    sprintf(ret, "%s%s%s", cpl_cmd, SH_AND_STR, lnk_cmd);
    return ret;
}

char *so_command(const char *filename)
{
    (void)filename;
    // fPic is not needed on current versions of arch
    return "gcc -Wall -Wextra -Werror -std=c99 -pedantic "
           "-shared -o test.so -fPIC -c "TST_FILE_PATH;
}

int build(const char *filename)
{
#if OPT_KEEP_OBJECT == 1
    const char *cpl_cmd = compile_command(filename);
    const char *lnk_cmd = link_command(filename);
    char *command = build_full_command(cpl_cmd, lnk_cmd);
    int ret = system(command);

    free(command);
    return ret;
#else
    return system(so_command(filename));
#endif
}
