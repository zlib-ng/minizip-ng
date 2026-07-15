/* mz_strm_posix.c -- Stream for filesystem access for posix/linux
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng
   Modifications for Zip64 support
     Copyright (C) 2009-2010 Mathias Svensson
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     https://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_config.h"
#include "mz_strm.h"
#include "mz_strm_os.h"

#include <stdio.h> /* fopen, fread, ... */
#include <errno.h>
#include <sys/stat.h> /* S_IRUSR, S_IWUSR, ... */
#include <unistd.h>   /* open, close, ... */
#include <fcntl.h>    /* O_NOFOLLOW, ... */

#ifndef O_DIRECTORY
#  define O_DIRECTORY 0
#endif
#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

/***************************************************************************/

#define fopen64 fopen
#ifndef MZ_FILE32_API
#  if HAVE_FSEEKO
#    define ftello64 ftello
#    define fseeko64 fseeko
#  elif defined(_MSC_VER) && (_MSC_VER >= 1400)
#    define ftello64 _ftelli64
#    define fseeko64 _fseeki64
#  endif
#endif
#ifndef ftello64
#  define ftello64 ftell
#endif
#ifndef fseeko64
#  define fseeko64 fseek
#endif

/***************************************************************************/

static mz_stream_vtbl mz_stream_os_vtbl = {mz_stream_os_open,
                                           mz_stream_os_is_open,
                                           mz_stream_os_read,
                                           mz_stream_os_write,
                                           mz_stream_os_tell,
                                           mz_stream_os_seek,
                                           mz_stream_os_close,
                                           mz_stream_os_error,
                                           mz_stream_os_create,
                                           mz_stream_os_delete,
                                           NULL,
                                           NULL};

/***************************************************************************/

typedef struct mz_stream_posix_s {
    mz_stream stream;
    int32_t error;
    FILE *handle;
} mz_stream_posix;

/***************************************************************************/

static int mz_stream_open_parent_nofollow(const char *path) {
    char *parent = NULL;
    char *component = NULL;
    char *saveptr = NULL;
    char *slash = NULL;
    int current_fd = -1;
    int next_fd = -1;

    parent = strdup(path);
    if (!parent)
        return -1;

    slash = strrchr(parent, '/');
    if (slash) {
        *slash = 0;
        if (parent[0] == 0)
            strcpy(parent, "/");
    } else {
        strcpy(parent, ".");
    }

    current_fd = open(parent[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (current_fd == -1) {
        free(parent);
        return -1;
    }

    component = strtok_r(parent + (parent[0] == '/'), "/", &saveptr);
    while (component) {
        if (strcmp(component, ".") == 0 || component[0] == 0) {
            component = strtok_r(NULL, "/", &saveptr);
            continue;
        }
        if (strcmp(component, "..") == 0) {
            close(current_fd);
            free(parent);
            return -1;
        }
        next_fd = openat(current_fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd == -1) {
            close(current_fd);
            free(parent);
            return -1;
        }
        close(current_fd);
        current_fd = next_fd;
        component = strtok_r(NULL, "/", &saveptr);
    }

    free(parent);
    return current_fd;
}

static int mz_stream_open_nofollow(const char *path, int flags, mode_t mode) {
    char *filename = NULL;
    char *slash = NULL;
    int parent_fd = -1;
    int fd = -1;

    filename = strdup(path);
    if (!filename)
        return -1;
    slash = strrchr(filename, '/');
    if (slash)
        *slash = 0;
    parent_fd = mz_stream_open_parent_nofollow(path);
    if (parent_fd != -1) {
        fd = openat(parent_fd, slash ? slash + 1 : filename, flags | O_NOFOLLOW, mode);
        close(parent_fd);
    }
    free(filename);
    return fd;
}

int32_t mz_stream_os_open(void *stream, const char *path, int32_t mode) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    const char *mode_fopen = NULL;
    int mode_open = 0;
    int fd;

    if (!path)
        return MZ_PARAM_ERROR;

    if ((mode & MZ_OPEN_MODE_READWRITE) == MZ_OPEN_MODE_READ) {
        mode_fopen = "r";
        mode_open = O_RDONLY;
    } else if (mode & MZ_OPEN_MODE_APPEND) {
        mode_fopen = "r+";
        mode_open = O_RDWR;
    } else if (mode & MZ_OPEN_MODE_CREATE) {
        mode_fopen = "w";
        mode_open = O_WRONLY | O_CREAT | O_TRUNC;
    } else
        return MZ_OPEN_ERROR;

    if (mode & MZ_OPEN_MODE_NOFOLLOW)
        mode_open |= O_NOFOLLOW;

    if ((mode & (MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_NOFOLLOW)) ==
        (MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_NOFOLLOW))
        fd = mz_stream_open_nofollow(path, mode_open, S_IRUSR | S_IWUSR | S_IRGRP);
    else
        fd = open(path, mode_open, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd != -1) {
        posix->handle = fdopen(fd, mode_fopen);
        if (!posix->handle)
            close(fd);
    }
    if (!posix->handle) {
        posix->error = errno;
        return MZ_OPEN_ERROR;
    }

    if (mode & MZ_OPEN_MODE_APPEND)
        return mz_stream_os_seek(stream, 0, MZ_SEEK_END);

    return MZ_OK;
}

int32_t mz_stream_os_is_open(void *stream) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    if (!posix->handle)
        return MZ_OPEN_ERROR;
    return MZ_OK;
}

int32_t mz_stream_os_read(void *stream, void *buf, int32_t size) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    int32_t read = (int32_t)fread(buf, 1, (size_t)size, posix->handle);
    if (read < size && ferror(posix->handle)) {
        posix->error = errno;
        return MZ_READ_ERROR;
    }
    return read;
}

int32_t mz_stream_os_write(void *stream, const void *buf, int32_t size) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    int32_t written = (int32_t)fwrite(buf, 1, (size_t)size, posix->handle);
    if (written < size && ferror(posix->handle)) {
        posix->error = errno;
        return MZ_WRITE_ERROR;
    }
    return written;
}

int64_t mz_stream_os_tell(void *stream) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    int64_t position = ftello64(posix->handle);
    if (position == -1) {
        posix->error = errno;
        return MZ_TELL_ERROR;
    }
    return position;
}

int32_t mz_stream_os_seek(void *stream, int64_t offset, int32_t origin) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    int32_t fseek_origin = 0;

    switch (origin) {
    case MZ_SEEK_CUR:
        fseek_origin = SEEK_CUR;
        break;
    case MZ_SEEK_END:
        fseek_origin = SEEK_END;
        break;
    case MZ_SEEK_SET:
        fseek_origin = SEEK_SET;
        break;
    default:
        return MZ_SEEK_ERROR;
    }

    if (fseeko64(posix->handle, offset, fseek_origin) != 0) {
        posix->error = errno;
        return MZ_SEEK_ERROR;
    }

    return MZ_OK;
}

int32_t mz_stream_os_close(void *stream) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    int32_t closed = 0;
    if (posix->handle) {
        closed = fclose(posix->handle);
        posix->handle = NULL;
    }
    if (closed != 0) {
        posix->error = errno;
        return MZ_CLOSE_ERROR;
    }
    return MZ_OK;
}

int32_t mz_stream_os_error(void *stream) {
    mz_stream_posix *posix = (mz_stream_posix *)stream;
    return posix->error;
}

void *mz_stream_os_create(void) {
    mz_stream_posix *posix = (mz_stream_posix *)calloc(1, sizeof(mz_stream_posix));
    if (posix)
        posix->stream.vtbl = &mz_stream_os_vtbl;
    return posix;
}

void mz_stream_os_delete(void **stream) {
    mz_stream_posix *posix = NULL;
    if (!stream)
        return;
    posix = (mz_stream_posix *)*stream;
    free(posix);
    *stream = NULL;
}

void *mz_stream_os_get_interface(void) {
    return (void *)&mz_stream_os_vtbl;
}
