/* mzstrm_mem.h -- Stream for memory access
   part of MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip
   Copyright (C) 2003 Justin Fletcher
   Copyright (C) 1998-2003 Gilles Vollant

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_MEM_H
#define _MZ_STREAM_MEM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t mz_stream_mem_open(void *stream, const char* filename, int mode);
int32_t mz_stream_mem_read(void *stream, void* buf, uint32_t size);
int32_t mz_stream_mem_write(void *stream, const void* buf, uint32_t size);
int64_t mz_stream_mem_tell(void *stream);
int32_t mz_stream_mem_seek(void *stream, uint64_t offset, int origin);
int32_t mz_stream_mem_close(void *stream);
int32_t mz_stream_mem_error(void *stream);

void    mz_stream_mem_set_buffer(void *stream, void *buf, uint32_t size);
void    mz_stream_mem_set_growable(void *stream, int growable);

void*   mz_stream_mem_create(void **stream);
void    mz_stream_mem_delete(void **stream);

#ifdef __cplusplus
}
#endif

#endif
