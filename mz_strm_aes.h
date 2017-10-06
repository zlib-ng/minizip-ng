/* mz_strm_aes.h -- Stream for WinZIP AES encryption
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

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

/***************************************************************************/

#define MZ_AES_METHOD          (99)
#define MZ_AES_VERSION         (0x0001)
#define MZ_AES_ENCRYPTIONMODE  (0x03)

/***************************************************************************/

int32_t mz_stream_aes_open(void *stream, const char *filename, int32_t mode);
int32_t mz_stream_aes_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_aes_write(void *stream, const void *buf, int32_t size);
int64_t mz_stream_aes_tell(void *stream);
int32_t mz_stream_aes_seek(void *stream, int64_t offset, int32_t origin);
int32_t mz_stream_aes_close(void *stream);
int32_t mz_stream_aes_error(void *stream);

void    mz_stream_aes_set_password(void *stream, const char *password);
void    mz_stream_aes_set_encryption_mode(void *stream, int16_t encryption_mode);
int64_t mz_stream_aes_get_total_in(void *stream);
int64_t mz_stream_aes_get_total_out(void *stream);
int32_t mz_stream_aes_get_footer_size(void *stream);

void*   mz_stream_aes_create(void **stream);
void    mz_stream_aes_delete(void **stream);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
