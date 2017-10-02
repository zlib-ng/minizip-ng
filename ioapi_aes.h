/* ioapi_aes.h -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _IOAPI_AES_H
#define _IOAPI_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t ZCALLBACK mz_stream_aes_open(voidpf stream, const char* filename, int mode);
int32_t ZCALLBACK mz_stream_aes_read(voidpf stream, void* buf, uint32_t size);
int32_t ZCALLBACK mz_stream_aes_write(voidpf stream, const void* buf, uint32_t size);
int64_t ZCALLBACK mz_stream_aes_tell(voidpf stream);
int32_t ZCALLBACK mz_stream_aes_seek(voidpf stream, uint64_t offset, int origin);
int32_t ZCALLBACK mz_stream_aes_close(voidpf stream);
int32_t ZCALLBACK mz_stream_aes_error(voidpf stream);

void              mz_stream_aes_set_password(voidpf stream, char *password);
void              mz_stream_aes_set_encryption_mode(voidpf stream, int16_t encryption_mode);

voidpf            mz_stream_aes_create(voidpf *stream);
void              mz_stream_aes_delete(voidpf *stream);

#ifdef __cplusplus
}
#endif

#endif
