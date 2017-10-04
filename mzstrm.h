/* mzstrm.h -- Stream interface
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

#ifndef _MZ_STREAM_H
#define _MZ_STREAM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#define MZ_STREAM_SEEK_CUR              (1)
#define MZ_STREAM_SEEK_END              (2)
#define MZ_STREAM_SEEK_SET              (0)

#define MZ_STREAM_MODE_READ             (1)
#define MZ_STREAM_MODE_WRITE            (2)
#define MZ_STREAM_MODE_READWRITEFILTER  (3)
#define MZ_STREAM_MODE_EXISTING         (4)
#define MZ_STREAM_MODE_CREATE           (8)

#ifndef MZ_RETURN
#  define MZ_OK                         (0)
#  define MZ_EOF                        (MZ_OK)
#  define MZ_STREAM_ERROR               (-1)
#  define MZ_END_OF_LIST                (-100)
#  define MZ_PARAM_ERROR                (-102)
#  define MZ_FORMAT_ERROR               (-103)
#  define MZ_INTERNAL_ERROR             (-104)
#  define MZ_CRC_ERROR                  (-105)
#  define MZ_CRYPT_ERROR                (-106)
#endif

/***************************************************************************/

typedef int32_t (*mz_stream_open_cb)           (void *stream, const char *path, int mode);
typedef int32_t (*mz_stream_is_open_cb)        (void *stream);
typedef int32_t (*mz_stream_read_cb)           (void *stream, void* buf, uint32_t size);
typedef int32_t (*mz_stream_write_cb)          (void *stream, const void *buf, uint32_t size);
typedef int64_t (*mz_stream_tell_cb)           (void *stream);
typedef int32_t (*mz_stream_seek_cb)           (void *stream, uint64_t offset, int origin);
typedef int32_t (*mz_stream_close_cb)          (void *stream);
typedef int32_t (*mz_stream_error_cb)          (void *stream);
typedef void*   (*mz_stream_create_cb)         (void **stream);
typedef void    (*mz_stream_delete_cb)         (void **stream);
typedef int64_t (*mz_stream_get_total_in_cb)   (void *stream);
typedef int64_t (*mz_stream_get_total_out_cb)  (void *stream);

/***************************************************************************/

typedef struct mz_stream_s
{
    struct mz_stream_s          *base;
    mz_stream_open_cb           open;
    mz_stream_is_open_cb        is_open;
    mz_stream_read_cb           read;
    mz_stream_write_cb          write;
    mz_stream_tell_cb           tell;
    mz_stream_seek_cb           seek;
    mz_stream_close_cb          close;
    mz_stream_error_cb          error;
    mz_stream_create_cb         create;
    mz_stream_delete_cb         delete;
    mz_stream_get_total_in_cb   get_total_in;
    mz_stream_get_total_out_cb  get_total_out;
} mz_stream;

/***************************************************************************/

int32_t mz_stream_open(void *stream, const char *path, int mode);
int32_t mz_stream_is_open(void *stream);
int32_t mz_stream_read(void *stream, void* buf, uint32_t size);
int32_t mz_stream_read_uint8(void *stream, uint8_t *value);
int32_t mz_stream_read_uint16(void *stream, uint16_t *value);
int32_t mz_stream_read_uint32(void *stream, uint32_t *value);
int32_t mz_stream_read_uint64(void *stream, uint64_t *value);
int32_t mz_stream_write(void *stream, const void *buf, uint32_t size);
int32_t mz_stream_write_uint8(void *stream, uint8_t value);
int32_t mz_stream_write_uint16(void *stream, uint16_t value);
int32_t mz_stream_write_uint32(void *stream, uint32_t value);
int32_t mz_stream_write_uint64(void *stream, uint64_t value);
int32_t mz_stream_copy(void *target, void *source, int32_t len);
int64_t mz_stream_tell(void *stream);
int32_t mz_stream_seek(void *stream, uint64_t offset, int origin);
int32_t mz_stream_close(void *stream);
int32_t mz_stream_error(void *stream);

int32_t mz_stream_set_base(void *stream, void *base);
int64_t mz_stream_get_total_in(void *stream);
int64_t mz_stream_get_total_out(void *stream);

void*   mz_stream_create(void **stream);
void    mz_stream_delete(void **stream);

void*   mz_stream_passthru_create(void **stream);
void    mz_stream_passthru_delete(void **stream);

/***************************************************************************/

#if !defined(_WIN32) && !defined(USEWIN32IOAPI)
#include "mzstrm_posix.h"

#define mz_stream_os_open    mz_stream_posix_open
#define mz_stream_os_is_open mz_stream_posix_is_open
#define mz_stream_os_read    mz_stream_posix_read
#define mz_stream_os_write   mz_stream_posix_write
#define mz_stream_os_tell    mz_stream_posix_tell
#define mz_stream_os_seek    mz_stream_posix_seek
#define mz_stream_os_close   mz_stream_posix_close
#define mz_stream_os_error   mz_stream_posix_error

#define mz_stream_os_create  mz_stream_posix_create
#define mz_stream_os_delete  mz_stream_posix_delete

#define mz_os_rand           mz_posix_rand
#else
#include "mzstrm_win32.h"

#define mz_stream_os_open    mz_stream_win32_open
#define mz_stream_os_is_open mz_stream_win32_is_open
#define mz_stream_os_read    mz_stream_win32_read
#define mz_stream_os_write   mz_stream_win32_write
#define mz_stream_os_tell    mz_stream_win32_tell
#define mz_stream_os_seek    mz_stream_win32_seek
#define mz_stream_os_close   mz_stream_win32_close
#define mz_stream_os_error   mz_stream_win32_error

#define mz_stream_os_create  mz_stream_win32_create
#define mz_stream_os_delete  mz_stream_win32_delete

#define mz_os_rand           mz_win32_rand
#endif

int32_t mz_os_file_exists(const char *path);
int32_t mz_os_file_is_large(const char *path);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
