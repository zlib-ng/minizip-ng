/* mz_strm_zlib.h -- Stream for zlib inflate/deflate
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_ZLIB_H
#define _MZ_STREAM_ZLIB_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t mz_stream_zlib_open(void *stream, const char *filename, int32_t mode);
int32_t mz_stream_zlib_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_zlib_write(void *stream, const void *buf, int32_t size);
int64_t mz_stream_zlib_tell(void *stream);
int32_t mz_stream_zlib_seek(void *stream, int64_t offset, int32_t origin);
int32_t mz_stream_zlib_close(void *stream);
int32_t mz_stream_zlib_error(void *stream);

void    mz_stream_zlib_set_level(void *stream, int16_t level);
void    mz_stream_zlib_set_window_bits(void *stream, int16_t window_bits);
void    mz_stream_zlib_set_mem_level(void *stream, int16_t mem_level);
void    mz_stream_zlib_set_strategy(void *stream, int16_t strategy);
int64_t mz_stream_zlib_get_total_in(void *stream);
int64_t mz_stream_zlib_get_total_out(void *stream);
void    mz_stream_zlib_set_max_total_in(void *stream, int64_t max_total_in);

void*   mz_stream_zlib_create(void **stream);
void    mz_stream_zlib_delete(void **stream);

/***************************************************************************/

int32_t mz_stream_crc32_open(void *stream, const char *filename, int32_t mode);
int32_t mz_stream_crc32_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_crc32_write(void *stream, const void *buf, int32_t size);
int64_t mz_stream_crc32_tell(void *stream);
int32_t mz_stream_crc32_seek(void *stream, int64_t offset, int32_t origin);
int32_t mz_stream_crc32_close(void *stream);
int32_t mz_stream_crc32_error(void *stream);

int32_t mz_stream_crc32_get_value(void *stream);
int64_t mz_stream_crc32_get_total_in(void *stream);
int64_t mz_stream_crc32_get_total_out(void *stream);

void*   mz_stream_crc32_create(void **stream);
void    mz_stream_crc32_delete(void **stream);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
