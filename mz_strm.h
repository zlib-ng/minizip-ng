/* mz_strm.h -- Stream interface
   Version 2.0.0, October 4th, 2017
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

#define MZ_STREAM_MODE_READ             (0x01)
#define MZ_STREAM_MODE_WRITE            (0x02)
#define MZ_STREAM_MODE_READWRITE        (MZ_STREAM_MODE_READ | MZ_STREAM_MODE_WRITE)
#define MZ_STREAM_MODE_APPEND           (0x04)
#define MZ_STREAM_MODE_CREATE           (0x08)
#define MZ_STREAM_MODE_EXISTING         (0x10)

/***************************************************************************/

typedef int32_t (*mz_stream_open_cb)           (void *stream, const char *path, int32_t mode);
typedef int32_t (*mz_stream_is_open_cb)        (void *stream);
typedef int32_t (*mz_stream_read_cb)           (void *stream, void *buf, int32_t size);
typedef int32_t (*mz_stream_write_cb)          (void *stream, const void *buf, int32_t size);
typedef int64_t (*mz_stream_tell_cb)           (void *stream);
typedef int32_t (*mz_stream_seek_cb)           (void *stream, int64_t offset, int32_t origin);
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

int32_t mz_stream_open(void *stream, const char *path, int32_t mode);
int32_t mz_stream_is_open(void *stream);
int32_t mz_stream_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_read_uint8(void *stream, uint8_t *value);
int32_t mz_stream_read_uint16(void *stream, uint16_t *value);
int32_t mz_stream_read_uint32(void *stream, uint32_t *value);
int32_t mz_stream_read_uint64(void *stream, uint64_t *value);
int32_t mz_stream_write(void *stream, const void *buf, int32_t size);
int32_t mz_stream_write_uint8(void *stream, uint8_t value);
int32_t mz_stream_write_uint16(void *stream, uint16_t value);
int32_t mz_stream_write_uint32(void *stream, uint32_t value);
int32_t mz_stream_write_uint64(void *stream, uint64_t value);
int32_t mz_stream_copy(void *target, void *source, int32_t len);
int64_t mz_stream_tell(void *stream);
int32_t mz_stream_seek(void *stream, int64_t offset, int32_t origin);
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

#ifdef __cplusplus
}
#endif

#endif
