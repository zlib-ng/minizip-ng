/* mzstrm_aes.h -- Stream for WinZIP AES encryption

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_AES_H
#define _MZ_STREAM_AES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t mz_stream_aes_open(void *stream, const char* filename, int mode);
int32_t mz_stream_aes_read(void *stream, void* buf, uint32_t size);
int32_t mz_stream_aes_write(void *stream, const void* buf, uint32_t size);
int64_t mz_stream_aes_tell(void *stream);
int32_t mz_stream_aes_seek(void *stream, uint64_t offset, int origin);
int32_t mz_stream_aes_close(void *stream);
int32_t mz_stream_aes_error(void *stream);

void    mz_stream_aes_set_password(void *stream, const char *password);
void    mz_stream_aes_set_encryption_mode(void *stream, int16_t encryption_mode);

void*   mz_stream_aes_create(void **stream);
void    mz_stream_aes_delete(void **stream);

#ifdef __cplusplus
}
#endif

#endif
