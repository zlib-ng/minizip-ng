/* ioapi_mem.h -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   This version of ioapi is designed to access memory rather than files.
   We do use a region of memory to put data in to and take it out of.

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip
   Copyright (C) 2003 Justin Fletcher
   Copyright (C) 1998-2003 Gilles Vollant

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_MEM_H
#define _MZ_STREAM_MEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ZCALLBACK mz_stream_mem_open(voidpf stream, const char* filename, int mode);
int32_t ZCALLBACK mz_stream_mem_read(voidpf stream, void* buf, uint32_t size);
int32_t ZCALLBACK mz_stream_mem_write(voidpf stream, const void* buf, uint32_t size);
int64_t ZCALLBACK mz_stream_mem_tell(voidpf stream);
int32_t ZCALLBACK mz_stream_mem_seek(voidpf stream, uint64_t offset, int origin);
int32_t ZCALLBACK mz_stream_mem_close(voidpf stream);
int32_t ZCALLBACK mz_stream_mem_error(voidpf stream);

void              mz_stream_mem_set_buffer(voidpf stream, void *buf, uint32_t size);
void              mz_stream_mem_set_growable(voidpf stream, int growable);

voidpf            mz_stream_mem_create(voidpf *stream);
void              mz_stream_mem_delete(voidpf *stream);

#ifdef __cplusplus
}
#endif

#endif
