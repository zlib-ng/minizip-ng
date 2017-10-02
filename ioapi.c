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

#include "ioapi.h"

int32_t mz_stream_open(voidpf stream, const char *filename, int mode)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->open == NULL)
        return MZ_STREAM_ERR;
    return strm->open(strm, filename, mode);
}

int32_t mz_stream_is_open(voidpf stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->is_open == NULL)
        return MZ_STREAM_ERR;
    return strm->is_open(strm);
}

int32_t mz_stream_read(voidpf stream, void* buf, uint32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->read == NULL)
        return MZ_STREAM_ERR;
    return strm->read(strm, buf, size);
}

int32_t mz_stream_write(voidpf stream, const void *buf, uint32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->write == NULL)
        return MZ_STREAM_ERR;
    return strm->write(strm, buf, size);
}

int64_t mz_stream_tell(voidpf stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->tell == NULL)
        return MZ_STREAM_ERR;
    return strm->tell(strm);
}

int32_t mz_stream_seek(voidpf stream, uint64_t offset, int origin)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->seek == NULL)
        return MZ_STREAM_ERR;
    return strm->seek(strm, offset, origin);
}

int32_t mz_stream_close(voidpf stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->close == NULL)
        return MZ_STREAM_ERR;
    return strm->close(strm);
}

int32_t mz_stream_error(voidpf stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->error == NULL)
        return MZ_STREAM_ERR;
    return strm->error(strm);
}

int32_t mz_stream_set_base(voidpf stream, voidpf base)
{
    mz_stream *strm = (mz_stream *)stream;
    strm->base = (mz_stream *)base;
    return MZ_STREAM_OK;
}
