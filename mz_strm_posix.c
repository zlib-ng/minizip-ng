/* mzstrm_posix.c -- Stream for filesystem access for posix/linux
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Modifications for Zip64 support
     Copyright (C) 2009-2010 Mathias Svensson
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

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
#elif defined _WIN32
#  include <sys/utime.h>
#  include <direct.h>
#  include <io.h>
#  define chdir(x)   _chdir(x)
#  define mkdir(x,y) _mkdir(x)
#endif

#include "mz_strm.h"
#include "mz_strm_posix.h"

/***************************************************************************/

#if defined(USE_FILE32API)
#  define fopen64 fopen
#  define ftello64 ftell
#  define fseeko64 fseek
#else
#  if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || \
      defined(__OpenBSD__) || defined(__APPLE__) || defined(__ANDROID__)
#    define fopen64 fopen
#    define ftello64 ftello
#    define fseeko64 fseeko
#  endif
#  ifdef _MSC_VER
#    define fopen64 fopen
#    if (_MSC_VER >= 1400) && (!(defined(NO_MSCVER_FILE64_FUNC)))
#      define ftello64 _ftelli64
#      define fseeko64 _fseeki64
#    else /* old MSC */
#      define ftello64 ftell
#      define fseeko64 fseek
#    endif
#  endif
#endif

#ifndef ZCR_SEED2
#  define ZCR_SEED2 3141592654UL     // use PI as default pattern
#endif

/***************************************************************************/

typedef struct mz_stream_posix_s
{
    mz_stream   stream;
    FILE        *handle;
    int16_t     error;
} mz_stream_posix;

/***************************************************************************/

int32_t mz_stream_posix_open(void *stream, const char *path, int mode)
{
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    const char *mode_fopen = NULL;

    if (path == NULL)
        return MZ_STREAM_ERROR;

    if ((mode & MZ_STREAM_MODE_READWRITE) == MZ_STREAM_MODE_READ)
        mode_fopen = "rb";
    else if (mode & MZ_STREAM_MODE_APPEND)
        mode_fopen = "ab";
    else if (mode & MZ_STREAM_MODE_CREATE)
        mode_fopen = "wb";
    else
        return MZ_STREAM_ERROR;

    posix->handle = fopen64(path, mode_fopen);
    if (posix->handle == NULL)
    {
        posix->error = errno;
        return MZ_STREAM_ERROR;
    }

    return MZ_OK;
}

int32_t mz_stream_posix_is_open(void *stream)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    if (posix->handle == NULL)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_posix_read(void *stream, void* buf, uint32_t size)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    int32_t read = (int32_t)fread(buf, 1, (size_t)size, posix->handle);
    if (read < 0)
    {
        posix->error = ferror(posix->handle);
        return MZ_STREAM_ERROR;
    }
    return read;
}

int32_t mz_stream_posix_write(void *stream, const void *buf, uint32_t size)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    int32_t written = (int32_t)fwrite(buf, 1, (size_t)size, posix->handle);
    if (written < 0)
    {
        posix->error = ferror(posix->handle);
        return MZ_STREAM_ERROR;
    }
    return written;
}

int64_t mz_stream_posix_tell(void *stream)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    int64_t position = ftello64(posix->handle);
    if (position == -1)
    {
        posix->error = ferror(posix->handle);
        return MZ_STREAM_ERROR;
    }
    return position;
}

int32_t mz_stream_posix_seek(void *stream, uint64_t offset, int origin)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    int fseek_origin = 0;

    switch (origin)
    {
        case MZ_STREAM_SEEK_CUR:
            fseek_origin = SEEK_CUR;
            break;
        case MZ_STREAM_SEEK_END:
            fseek_origin = SEEK_END;
            break;
        case MZ_STREAM_SEEK_SET:
            fseek_origin = SEEK_SET;
            break;
        default:
            return MZ_STREAM_ERROR;
    }

    if (fseeko64(posix->handle, offset, fseek_origin) != 0)
    {
        posix->error = ferror(posix->handle);
        return MZ_STREAM_ERROR;
    }

    return MZ_OK;
}

int32_t mz_stream_posix_close(void *stream)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    int32_t closed = fclose(posix->handle);
    posix->handle = NULL;
    if (closed != 0)
    {
        posix->error = errno;
        return MZ_STREAM_ERROR;
    }
    return MZ_OK;
}

int32_t mz_stream_posix_error(void *stream)
{
    mz_stream_posix *posix = (mz_stream_posix*)stream;
    return posix->error;
}

void *mz_stream_posix_create(void **stream)
{
    mz_stream_posix *posix = NULL;

    posix = (mz_stream_posix *)malloc(sizeof(mz_stream_posix));
    if (posix != NULL)
    {
        posix->stream.open = mz_stream_posix_open;
        posix->stream.is_open = mz_stream_posix_is_open;
        posix->stream.read = mz_stream_posix_read;
        posix->stream.write = mz_stream_posix_write;
        posix->stream.tell = mz_stream_posix_tell;
        posix->stream.seek = mz_stream_posix_seek;
        posix->stream.close = mz_stream_posix_close;
        posix->stream.error = mz_stream_posix_error;
        posix->stream.create = mz_stream_posix_create;
        posix->stream.delete = mz_stream_posix_delete;
    }
    if (stream != NULL)
        *stream = posix;

    return posix;
}

void mz_stream_posix_delete(void **stream)
{
    mz_stream_posix *posix = NULL;
    if (stream == NULL)
        return;
    posix = (mz_stream_posix *)*stream;
    if (posix != NULL)
        free(posix);
    *stream = NULL;
}

/***************************************************************************/

int32_t mz_posix_rand(uint8_t *buf, uint32_t size)
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
