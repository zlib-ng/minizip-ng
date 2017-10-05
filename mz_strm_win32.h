/* mzstrm_win32.h -- Stream for filesystem access for windows
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

#ifndef _MZ_STREAM_WIN32_H
#define _MZ_STREAM_WIN32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t mz_stream_win32_open(void *stream, const char *path, int mode);
int32_t mz_stream_win32_is_open(void *stream);
int32_t mz_stream_win32_read(void *stream, void* buf, uint32_t size);
int32_t mz_stream_win32_write(void *stream, const void *buf, uint32_t size);
int64_t mz_stream_win32_tell(void *stream);
int32_t mz_stream_win32_seek(void *stream, uint64_t offset, int origin);
int32_t mz_stream_win32_close(void *stream);
int32_t mz_stream_win32_error(void *stream);

void*   mz_stream_win32_create(void **stream);
void    mz_stream_win32_delete(void **stream);

/***************************************************************************/

int32_t mz_win32_rand(uint8_t *buf, uint32_t size);
int16_t mz_win32_get_file_date(const char *path, uint32_t *dos_date);
int16_t mz_win32_set_file_date(const char *path, uint32_t dos_date);
int16_t mz_win32_change_dir(const char *path);
int16_t mz_win32_make_dir(const char *path);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
