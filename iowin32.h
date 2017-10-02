/* iowin32.h -- IO base function header for compress/uncompress .zip
   Version 1.2.0, September 16th, 2017
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

#ifndef _MZSTREAM_WIN32_H
#define _MZSTREAM_WIN32_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t ZCALLBACK mzstream_win32_open(voidpf stream, const char *filename, int mode);
int32_t ZCALLBACK mzstream_win32_is_open(voidpf stream);
int32_t ZCALLBACK mzstream_win32_read(voidpf stream, void* buf, uint32_t size);
int32_t ZCALLBACK mzstream_win32_write(voidpf stream, const void *buf, uint32_t size);
int64_t ZCALLBACK mzstream_win32_tell(voidpf stream);
int32_t ZCALLBACK mzstream_win32_seek(voidpf stream, uint64_t offset, int origin);
int32_t ZCALLBACK mzstream_win32_close(voidpf stream);
int32_t ZCALLBACK mzstream_win32_error(voidpf stream);

voidpf            mzstream_win32_alloc(void);
void              mzstream_win32_free(voidpf stream);

int32_t           mzstream_win32_rand(uint8_t *buf, uint16_t size);

#ifdef __cplusplus
}
#endif

#endif
