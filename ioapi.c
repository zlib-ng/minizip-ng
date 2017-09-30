/* ioapi.c -- IO base function header for compress/uncompress .zip
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Modifications for Zip64 support
     Copyright (C) 2009-2010 Mathias Svensson
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <string.h>

#if defined unix || defined __APPLE__
#include <sys/types.h>
#include <unistd.h>
#endif

#include "ioapi.h"

#if defined(USE_FILE32API)
#  define fopen64 fopen
#  define ftello64 ftell
#  define fseeko64 fseek
#else
#  if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__DragonFly__) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__ANDROID__)
#    define fopen64 fopen
#    define ftello64 ftello
#    define fseeko64 fseeko
#  endif
#  ifdef _MSC_VER
#    define fopen64 fopen
#    if (_MSC_VER >= 1400) && (!(defined(NO_MSCVER_FILE64_FUNC)))
#      define ftello64 _ftelli64
#      define fseeko64 _fseeki64
#    else /* old MSC */
#      define ftello64 ftell
#      define fseeko64 fseek
#    endif
#  endif
#endif

int32_t mzstream_open(voidpf stream, const char *filename, int mode)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->open == NULL)
        return MZSTREAM_ERR;
    return strm->open(strm, filename, mode);
}

int32_t mzstream_is_open(voidpf stream)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->is_open == NULL)
        return MZSTREAM_ERR;
    return strm->is_open(strm);
}

int32_t mzstream_read(voidpf stream, void* buf, uint32_t size)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->read == NULL)
        return MZSTREAM_ERR;
    return strm->read(strm, buf, size);
}

int32_t mzstream_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->write == NULL)
        return MZSTREAM_ERR;
    return strm->write(strm, buf, size);
}

int64_t mzstream_tell(voidpf stream)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->tell == NULL)
        return MZSTREAM_ERR;
    return strm->tell(strm);
}

int32_t mzstream_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->seek == NULL)
        return MZSTREAM_ERR;
    return strm->seek(strm, offset, origin);
}

int32_t mzstream_close(voidpf stream)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->close == NULL)
        return MZSTREAM_ERR;
    return strm->close(strm);
}

int32_t mzstream_error(voidpf stream)
{
    mzstream *strm = (mzstream *)stream;
    if (strm == NULL || strm->error == NULL)
        return MZSTREAM_ERR;
    return strm->error(strm);
}

int32_t mzstream_set_base(voidpf stream, voidpf base)
{
    mzstream *strm = (mzstream *)stream;
    strm->base = (mzstream *)base;
    return MZSTREAM_OK;
}
typedef struct mzstream_posix_s
{
    mzstream   stream;
    FILE        *handle;
    void        *filename;
    uint16_t    filename_size;
} mzstream_posix;

int32_t ZCALLBACK mzstream_posix_open(voidpf stream, const char *filename, int mode)
{
    mzstream_posix *posix = (mzstream_posix *)stream;
    const char *mode_fopen = NULL;

    if (filename == NULL)
        return MZSTREAM_ERR;

    if ((mode & MZSTREAM_MODE_READWRITEFILTER) == MZSTREAM_MODE_READ)
        mode_fopen = "rb";
    else if (mode & MZSTREAM_MODE_EXISTING)
        mode_fopen = "r+b";
    else if (mode & MZSTREAM_MODE_CREATE)
        mode_fopen = "wb";
    else
        return MZSTREAM_ERR;

    posix->handle = fopen64((const char*)filename, mode_fopen);
    strncpy((char *)posix->filename, filename, posix->filename_size);

    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_posix_is_open(voidpf stream)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    if (posix->handle == NULL)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_posix_read(voidpf stream, void* buf, uint32_t size)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    return (uint32_t)fread(buf, 1, (size_t)size, posix->handle);
}

int32_t ZCALLBACK mzstream_posix_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    return (uint32_t)fwrite(buf, 1, (size_t)size, posix->handle);
}

int64_t ZCALLBACK mzstream_posix_tell(voidpf stream)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    return ftello64(posix->handle);
}

int32_t ZCALLBACK mzstream_posix_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    int fseek_origin = 0;

    switch (origin)
    {
        case MZSTREAM_SEEK_CUR:
            fseek_origin = SEEK_CUR;
            break;
        case MZSTREAM_SEEK_END:
            fseek_origin = SEEK_END;
            break;
        case MZSTREAM_SEEK_SET:
            fseek_origin = SEEK_SET;
            break;
        default:
            return MZSTREAM_ERR;
    }

    if (fseeko64(posix->handle, offset, fseek_origin) != 0)
        return MZSTREAM_ERR;

    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_posix_close(voidpf stream)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    int closed = fclose(posix->handle);
    if (posix->filename != NULL)
        free(posix->filename);
    posix->handle = NULL;
    if (closed != 0)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_posix_error(voidpf stream)
{
    mzstream_posix *posix = (mzstream_posix*)stream;
    return ferror(posix->handle);
}

voidpf mzstream_posix_alloc(void)
{
    mzstream_posix *posix = NULL;

    posix = (mzstream_posix *)malloc(sizeof(mzstream_posix));
    if (posix == NULL)
        return NULL;

    posix->stream.open = mzstream_posix_open;
    posix->stream.is_open = mzstream_posix_is_open;
    posix->stream.read = mzstream_posix_read;
    posix->stream.write = mzstream_posix_write;
    posix->stream.tell = mzstream_posix_tell;
    posix->stream.seek = mzstream_posix_seek;
    posix->stream.close = mzstream_posix_close;
    posix->stream.error = mzstream_posix_error;
    posix->stream.alloc = mzstream_posix_alloc;
    posix->stream.free = mzstream_posix_free;

    return (voidpf)posix;
}

void mzstream_posix_free(voidpf stream)
{
    mzstream_posix *posix = (mzstream_posix *)stream;
    if (posix != NULL)
        free(posix);
}