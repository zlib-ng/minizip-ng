/* mz_strm_crc32.h -- Stream for CRC32 hashing
   Version 2.7.1, November 1, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_STREAM_CRC32_H
#define MZ_STREAM_CRC32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

typedef int64_t (*mz_stream_crc32_update)(int64_t value, const void *buf, int32_t size);

int32_t  mz_stream_crc32_open(void *stream, const char *filename, int32_t mode);
int32_t  mz_stream_crc32_is_open(void *stream);
int32_t  mz_stream_crc32_read(void *stream, void *buf, int32_t size);
int32_t  mz_stream_crc32_write(void *stream, const void *buf, int32_t size);
int64_t  mz_stream_crc32_tell(void *stream);
int32_t  mz_stream_crc32_seek(void *stream, int64_t offset, int32_t origin);
int32_t  mz_stream_crc32_close(void *stream);
int32_t  mz_stream_crc32_error(void *stream);

uint32_t mz_stream_crc32_get_value(void *stream);

int32_t  mz_stream_crc32_get_prop_int64(void *stream, int32_t prop, int64_t *value);

void*    mz_stream_crc32_create(void **stream);
void     mz_stream_crc32_delete(void **stream);

void*    mz_stream_crc32_get_interface(void);
int32_t  mz_stream_crc32_get_update_func(mz_stream_crc32_update *update);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
