#ifndef BUILD_H
# define BUILD_H

#define SH_AND_STR " && "
#define SH_AND_LEN 4

const char *compile_command(const char *filename);

const char *link_command(const char *filename);

char *so_command(const char *filename);

/*!
 * @brief build the shell command executing '@cpl_cmd && the @lnk_cmd'
 * @return Return the allocated string on success and null if malloc failed
 */
char *build_full_command(const char *cpl_cmd, const char *lnk_cmd);

/*!
 * @brief Compile @filename.
 * @return Return 0 on success and -1 if the build failed.
 */
int build(const char *filename);

#endif /* !BUILD_H */
