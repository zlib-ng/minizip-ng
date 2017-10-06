/* mz_strm_crypt.h -- Code for traditional PKWARE encryption
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2005 Gilles Vollant
     Modifications for Info-ZIP crypting
     http://www.winimage.com/zLibDll/minizip.html
   Copyright (C) 2003 Terry Thorsen

   This code is a modified version of crypting code in Info-ZIP distribution

   Copyright (C) 1990-2000 Info-ZIP.  All rights reserved.

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_CRYPT_H
#define _MZ_STREAM_CRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t mz_stream_crypt_open(void *stream, const char *filename, int32_t mode);
int32_t mz_stream_crypt_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_crypt_write(void *stream, const void *buf, int32_t size);
int64_t mz_stream_crypt_tell(void *stream);
int32_t mz_stream_crypt_seek(void *stream, int64_t offset, int32_t origin);
int32_t mz_stream_crypt_close(void *stream);
int32_t mz_stream_crypt_error(void *stream);

void    mz_stream_crypt_set_password(void *stream, const char *password);
void    mz_stream_crypt_set_verify(void *stream, uint8_t verify1, uint8_t verify2);
void    mz_stream_crypt_get_verify(void *stream, uint8_t *verify1, uint8_t *verify2);
int64_t mz_stream_crypt_get_total_in(void *stream);
int64_t mz_stream_crypt_get_total_out(void *stream);

void*   mz_stream_crypt_create(void **stream);
void    mz_stream_crypt_delete(void **stream);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
