/* mzstrm_posix.h -- Stream for filesystem access for posix/linux
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_STREAM_POSIX_H
#define _MZ_STREAM_POSIX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t mz_stream_posix_open(void *stream, const char *path, int32_t mode);
int32_t mz_stream_posix_is_open(void *stream);
int32_t mz_stream_posix_read(void *stream, void *buf, int32_t size);
int32_t mz_stream_posix_write(void *stream, const void *buf, int32_t size);
int64_t mz_stream_posix_tell(void *stream);
int32_t mz_stream_posix_seek(void *stream, int64_t offset, int32_t origin);
int32_t mz_stream_posix_close(void *stream);
int32_t mz_stream_posix_error(void *stream);

void*   mz_stream_posix_create(void **stream);
void    mz_stream_posix_delete(void **stream);

/***************************************************************************/

int32_t mz_posix_rand(uint8_t *buf, int32_t size);
int16_t mz_posix_get_file_date(const char *path, uint32_t *dos_date);
int16_t mz_posix_set_file_date(const char *path, uint32_t dos_date);
int16_t mz_posix_change_dir(const char *path);
int16_t mz_posix_make_dir(const char *path);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
