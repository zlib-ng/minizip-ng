/* mzstrm_buf.h -- Stream for buffering reads/writes
   part of MiniZip project

   This version of ioapi is designed to buffer IO.

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_BUFFERED_H
#define _MZ_STREAM_BUFFERED_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t mz_stream_buffered_open(void *stream, const char *path, int mode);
int32_t mz_stream_buffered_read(void *stream, void* buf, uint32_t size);
int32_t mz_stream_buffered_write(void *stream, const void *buf, uint32_t size);
int64_t mz_stream_buffered_tell(void *stream);
int32_t mz_stream_buffered_seek(void *stream, uint64_t offset, int origin);
int32_t mz_stream_buffered_close(void *stream);
int32_t mz_stream_buffered_error(void *stream);

void*   mz_stream_buffered_create(void **stream);
void    mz_stream_buffered_delete(void **stream);

#ifdef __cplusplus
}
#endif

#endif
