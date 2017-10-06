/* mz_os_posix.c -- System functions for posix
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#if defined unix || defined __APPLE__
#  include <unistd.h>
#  include <utime.h>
#  include <fcntl.h>
#endif

#include "mz_error.h"
#include "mz_strm.h"
#include "mz_os.h"
#include "mz_os_posix.h"

/***************************************************************************/

#ifndef ZCR_SEED2
#  define ZCR_SEED2 3141592654UL     // use PI as default pattern
#endif

/***************************************************************************/

int32_t mz_posix_rand(uint8_t *buf, int32_t size)
{
    static unsigned calls = 0;
    void *rand_stream = NULL;
    int32_t len = 0;


    if (mz_stream_posix_create(&rand_stream) == NULL)
        return 0;
    
    if (mz_stream_posix_open(rand_stream, "/dev/urandom", MZ_STREAM_MODE_READ) == MZ_OK)
    {
        len = mz_stream_posix_read(rand_stream, buf, size);
        mz_stream_posix_close(rand_stream);
    }

    mz_stream_posix_delete(&rand_stream);

    if (len < (int)size)
    {
        // Ensure different random header each time
        if (++calls == 1)
            srand((unsigned)(time(NULL) ^ ZCR_SEED2));

        while (len < (int)size)
            buf[len++] = (rand() >> 7) & 0xff;
    }
    return len;
}

int16_t mz_posix_get_file_date(const char *path, uint32_t *dos_date)
{
    struct stat stat_info;
    struct tm *filedate = NULL;
    time_t tm_t = 0;
    int16_t err = MZ_INTERNAL_ERROR;

    memset(&stat_info, 0, sizeof(stat_info));

    if (strcmp(path, "-") != 0)
    {
        size_t len = strlen(path);
        char *name = (char *)malloc(len + 1);
        strncpy(name, path, len + 1);
        name[len] = 0;
        if (name[len - 1] == '/')
            name[len - 1] = 0;

        /* Not all systems allow stat'ing a file with / appended */
        if (stat(name, &stat_info) == 0)
        {
            tm_t = stat_info.st_mtime;
            err = MZ_OK;
        }
        free(name);
    }

    filedate = localtime(&tm_t);
    *dos_date = mz_tm_to_dosdate(filedate);

    return err;
}

int16_t mz_posix_set_file_date(const char *path, uint32_t dos_date)
{
    struct utimbuf ut;

    ut.actime = mz_dosdate_to_time_t(dos_date);
    ut.modtime = mz_dosdate_to_time_t(dos_date);

    if (utime(path, &ut) != 0)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

int16_t mz_posix_change_dir(const char *path)
{
    if (chdir(path) != 0)
        return MZ_INTERNAL_ERROR;
    return MZ_OK;
}

int16_t mz_posix_make_dir(const char *path)
{
    int16_t err = 0;

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
    if (S_ISREG(path_stat.st_mode))
        return MZ_OK;
    return MZ_EXIST_ERROR;
}
