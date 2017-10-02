/* ioapi.h -- IO base function header for compress/uncompress .zip
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZSTREAM_H
#define _MZSTREAM_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "zlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ZCALLBACK
#  if (defined(WIN32) || defined(_WIN32) || defined (WINDOWS) || \
       defined (_WINDOWS)) && defined(CALLBACK) && defined (USEWINDOWS_CALLBACK)
#    define ZCALLBACK CALLBACK
#  else
#    define ZCALLBACK
#  endif
#endif
    
#define MZSTREAM_SEEK_CUR             (1)
#define MZSTREAM_SEEK_END             (2)
#define MZSTREAM_SEEK_SET             (0)

#define MZSTREAM_MODE_READ            (1)
#define MZSTREAM_MODE_WRITE           (2)
#define MZSTREAM_MODE_READWRITEFILTER (3)
#define MZSTREAM_MODE_EXISTING        (4)
#define MZSTREAM_MODE_CREATE          (8)

#define MZSTREAM_ERR                  (-1)
#define MZSTREAM_OK                   (0)

typedef int32_t (ZCALLBACK *mzstream_open_cb)     (voidpf stream, const char *filename, int mode);
typedef int32_t (ZCALLBACK *mzstream_is_open_cb)  (voidpf stream);
typedef int32_t (ZCALLBACK *mzstream_read_cb)     (voidpf stream, void* buf, uint32_t size);
typedef int32_t (ZCALLBACK *mzstream_write_cb)    (voidpf stream, const void *buf, uint32_t size);
typedef int64_t (ZCALLBACK *mzstream_tell_cb)     (voidpf stream);
typedef int32_t (ZCALLBACK *mzstream_seek_cb)     (voidpf stream, uint64_t offset, int origin);
typedef int32_t (ZCALLBACK *mzstream_close_cb)    (voidpf stream);
typedef int32_t (ZCALLBACK *mzstream_error_cb)    (voidpf stream);
typedef voidpf  (ZCALLBACK *mzstream_alloc_cb)    (void);
typedef void    (ZCALLBACK *mzstream_free_cb)     (voidpf stream);

typedef struct mzstream_s
{
    mzstream_open_cb      open;
    mzstream_is_open_cb   is_open;
    mzstream_read_cb      read;
    mzstream_write_cb     write;
    mzstream_tell_cb      tell;
    mzstream_seek_cb      seek;
    mzstream_close_cb     close;
    mzstream_error_cb     error;
    mzstream_alloc_cb     alloc;
    mzstream_free_cb      free;
    struct mzstream_s     *base;
} mzstream;

int32_t mzstream_open(voidpf stream, const char *filename, int mode);
int32_t mzstream_is_open(voidpf stream);
int32_t mzstream_read(voidpf stream, void* buf, uint32_t size);
int32_t mzstream_write(voidpf stream, const void *buf, uint32_t size);
int64_t mzstream_tell(voidpf stream);
int32_t mzstream_seek(voidpf stream, uint64_t offset, int origin);
int32_t mzstream_close(voidpf stream);
int32_t mzstream_error(voidpf stream);

int32_t mzstream_set_base(voidpf stream, voidpf base);

int32_t ZCALLBACK mzstream_posix_open(voidpf stream, const char *filename, int mode);
int32_t ZCALLBACK mzstream_posix_is_open(voidpf stream);
int32_t ZCALLBACK mzstream_posix_read(voidpf stream, void* buf, uint32_t size);
int32_t ZCALLBACK mzstream_posix_write(voidpf stream, const void *buf, uint32_t size);
int64_t ZCALLBACK mzstream_posix_tell(voidpf stream);
int32_t ZCALLBACK mzstream_posix_seek(voidpf stream, uint64_t offset, int origin);
int32_t ZCALLBACK mzstream_posix_close(voidpf stream);
int32_t ZCALLBACK mzstream_posix_error(voidpf stream);

voidpf             mzstream_posix_alloc(void);
void               mzstream_posix_free(voidpf stream);

int32_t            mzstream_posix_rand(uint8_t *buf, uint16_t size);

#ifndef _WIN32
#define mzstream_os_open    mzstream_posix_open
#define mzstream_os_is_open mzstream_posix_is_open
#define mzstream_os_read    mzstream_posix_read
#define mzstream_os_write   mzstream_posix_write
#define mzstream_os_tell    mzstream_posix_tell
#define mzstream_os_seek    mzstream_posix_seek
#define mzstream_os_close   mzstream_posix_close
#define mzstream_os_error   mzstream_posix_error

#define mzstream_os_alloc   mzstream_posix_alloc
#define mzstream_os_free    mzstream_posix_free

#define mzstream_os_rand    mzstream_posix_rand
#else
#include "iowin32.h"

#define mzstream_os_open    mzstream_win32_open
#define mzstream_os_is_open mzstream_win32_is_open
#define mzstream_os_read    mzstream_win32_read
#define mzstream_os_write   mzstream_win32_write
#define mzstream_os_tell    mzstream_win32_tell
#define mzstream_os_seek    mzstream_win32_seek
#define mzstream_os_close   mzstream_win32_close
#define mzstream_os_error   mzstream_win32_error

#define mzstream_os_alloc   mzstream_win32_alloc
#define mzstream_os_free    mzstream_win32_free

#define mzstream_os_rand    mzstream_win32_rand
#endif

#ifdef __cplusplus
}
#endif

#endif
