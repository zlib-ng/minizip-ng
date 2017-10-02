/* ioapi_buf.h -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   This version of ioapi is designed to buffer IO.

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZSTREAM_BUFFERED_H
#define _MZSTREAM_BUFFERED_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ZCALLBACK mzstream_buffered_open(voidpf stream, const char *filename, int mode);
int32_t ZCALLBACK mzstream_buffered_read(voidpf stream, void* buf, uint32_t size);
int32_t ZCALLBACK mzstream_buffered_write(voidpf stream, const void *buf, uint32_t size);
int64_t ZCALLBACK mzstream_buffered_tell(voidpf stream);
int32_t ZCALLBACK mzstream_buffered_seek(voidpf stream, uint64_t offset, int origin);
int32_t ZCALLBACK mzstream_buffered_close(voidpf stream);
int32_t ZCALLBACK mzstream_buffered_error(voidpf stream);

voidpf            mzstream_buffered_alloc(void);
void              mzstream_buffered_free(voidpf stream);

#ifdef __cplusplus
}
#endif

#endif
