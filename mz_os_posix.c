/* mz_os_posix.c -- System functions for posix
   Version 2.4.0, August 5, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_GETRANDOM
#  include <sys/random.h>
#endif
#if defined unix || defined __APPLE__
#  include <unistd.h>
#  include <utime.h>
#  define HAVE_ARC4RANDOM_BUF
#endif
#if defined __linux__
#  if !defined(MZ_ZIP_NO_COMPRESSION) && \
      !defined(MZ_ZIP_NO_ENCRYPTION) && \
       defined(HAVE_LIBBSD)
#    include <bsd/stdlib.h> // arc4random_buf
#  endif
#else
#  include <stdlib.h>
#endif

#include "mz.h"
#include "mz_strm.h"
#include "mz_os.h"
#include "mz_os_posix.h"

/***************************************************************************/

#if !defined(MZ_ZIP_NO_COMPRESSION) && !defined(MZ_ZIP_NO_ENCRYPTION)
#if defined(HAVE_LIBBSD) || defined(HAVE_ARC4RANDOM_BUF)
int32_t mz_posix_rand(uint8_t *buf, int32_t size)
{
    arc4random_buf(buf, size);
    return size;
}
#elif defined(HAVE_ARC4RANDOM)
int32_t mz_posix_rand(uint8_t *buf, int32_t size)
{
    int32_t left = size;
    for (; left > 2; left -= 3, buf += 3)
    {
        uint32_t val = arc4random();

        buf[0] = (val) & 0xFF;
        buf[1] = (val >> 8) & 0xFF;
        buf[2] = (val >> 16) & 0xFF;
    }
    for (; left > 0; left--, buf++)
    {
        *buf = arc4random() & 0xFF;
    }
    return size - left;
}
#elif defined(HAVE_GETRANDOM)
int32_t mz_posix_rand(uint8_t *buf, int32_t size)
{
    int32_t left = size;
    int32_t written = 0;

    while (left > 0)
    {
        written = getrandom(buf, left, 0);
        if (written < 0)
            return MZ_INTERNAL_ERROR;

        buf += written;
        left -= written;
    }
    return size - left;
}
#else
#if !defined(FORCE_LOWQUALITY_ENTROPY)
#  error "Low quality entropy function used for encryption"
#endif
int32_t mz_posix_rand(uint8_t *buf, int32_t size)
{
    static unsigned calls = 0;
    int32_t i = 0;

    // Ensure different random header each time
    if (++calls == 1)
    {
        #define PI_SEED 3141592654UL
        srand((unsigned)(time(NULL) ^ PI_SEED));
    }

    while (i < size)
        buf[i++] = (rand() >> 7) & 0xff;

    return size;
}
#endif
#endif

int32_t mz_posix_rename(const char *source_path, const char *target_path)
{
    if (rename(source_path, target_path) == -1)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_posix_delete(const char *path)
{
    if (unlink(path) == -1)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_posix_file_exists(const char *path)
{
    struct stat stat_info;

    memset(&stat_info, 0, sizeof(stat_info));
    if (stat(path, &stat_info) == 0)
        return MZ_OK;

    return MZ_EXIST_ERROR;
}

int64_t mz_posix_get_file_size(const char *path)
{
    struct stat stat_info;

    memset(&stat_info, 0, sizeof(stat_info));
    if (stat(path, &stat_info) == 0)
        return stat_info.st_size;

    return 0;
}

int32_t mz_posix_get_file_date(const char *path, time_t *modified_date, time_t *accessed_date, time_t *creation_date)
{
    struct stat stat_info;
    char *name = NULL;
    size_t len = 0;
    int32_t err = MZ_INTERNAL_ERROR;

    memset(&stat_info, 0, sizeof(stat_info));

    if (strcmp(path, "-") != 0)
    {
        // Not all systems allow stat'ing a file with / appended
        len = strlen(path);
        name = (char *)malloc(len + 1);
        strncpy(name, path, len + 1);
        name[len] = 0;
        if (name[len - 1] == '/')
            name[len - 1] = 0;

        if (stat(name, &stat_info) == 0)
        {
            if (modified_date != NULL)
                *modified_date = stat_info.st_mtime;
            if (accessed_date != NULL)
                *accessed_date = stat_info.st_atime;
            // Creation date not supported
            if (creation_date != NULL)
                *creation_date = 0;

            err = MZ_OK;
        }

        free(name);
    }

    return err;
}

int32_t mz_posix_set_file_date(const char *path, time_t modified_date, time_t accessed_date, time_t creation_date)
{
    struct utimbuf ut;

    ut.actime = accessed_date;
    ut.modtime = modified_date;
    // Creation date not supported
    (void)creation_date;

    if (utime(path, &ut) != 0)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

int32_t mz_posix_get_file_attribs(const char *path, uint32_t *attributes)
{
    struct stat stat_info;
    int32_t err = MZ_OK;

    memset(&stat_info, 0, sizeof(stat_info));
    if (stat(path, &stat_info) == -1)
        err = MZ_INTERNAL_ERROR;
    *attributes = stat_info.st_mode;
    return err;
}

int32_t mz_posix_set_file_attribs(const char *path, uint32_t attributes)
{
    int32_t err = MZ_OK;

    if (chmod(path, (mode_t)attributes) == -1)
        err = MZ_INTERNAL_ERROR;

    return err;
}

int32_t mz_posix_make_dir(const char *path)
{
    int32_t err = 0;

    err = mkdir(path, 0755);

    if (err != 0 && errno != EEXIST)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

DIR* mz_posix_open_dir(const char *path)
{
    return opendir(path);
}

struct dirent* mz_posix_read_dir(DIR *dir)
{
    if (dir == NULL)
        return NULL;
    return readdir(dir);
}

int32_t mz_posix_close_dir(DIR *dir)
{
    if (dir == NULL)
        return MZ_PARAM_ERROR;
    if (closedir(dir) == -1)
        return MZ_INTERNAL_ERROR;
    return MZ_OK;
}

int32_t mz_posix_is_dir(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    if (S_ISDIR(path_stat.st_mode))
        return MZ_OK;
    return MZ_EXIST_ERROR;
}
