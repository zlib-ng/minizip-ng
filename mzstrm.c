/* mzstrm.c -- Stream interface
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
#include <stdint.h>

#include "mzstrm.h"

int32_t mz_stream_open(void *stream, const char *path, int mode)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->open == NULL)
        return MZ_STREAM_ERR;
    return strm->open(strm, path, mode);
}

int32_t mz_stream_is_open(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->is_open == NULL)
        return MZ_STREAM_ERR;
    return strm->is_open(strm);
}

int32_t mz_stream_read(void *stream, void* buf, uint32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->read == NULL)
        return MZ_STREAM_ERR;
    return strm->read(strm, buf, size);
}

int32_t mz_stream_write(void *stream, const void *buf, uint32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->write == NULL)
        return MZ_STREAM_ERR;
    return strm->write(strm, buf, size);
}

int64_t mz_stream_tell(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->tell == NULL)
        return MZ_STREAM_ERR;
    return strm->tell(strm);
}

int32_t mz_stream_seek(void *stream, uint64_t offset, int origin)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->seek == NULL)
        return MZ_STREAM_ERR;
    return strm->seek(strm, offset, origin);
}

int32_t mz_stream_close(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->close == NULL)
        return MZ_STREAM_ERR;
    return strm->close(strm);
}

int32_t mz_stream_error(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->error == NULL)
        return MZ_STREAM_ERR;
    return strm->error(strm);
}

int32_t mz_stream_set_base(void *stream, void *base)
{
    mz_stream *strm = (mz_stream *)stream;
    strm->base = (mz_stream *)base;
    return MZ_STREAM_OK;
}

int32_t mz_os_file_exists(const char *path)
{
    void *stream = NULL;
    int opened = 0;

    mz_stream_os_create(&stream);

    if (mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        mz_stream_os_close(stream);
        opened = 1;
    }

    mz_stream_os_delete(&stream);

    return opened;
}

int32_t mz_os_file_is_large(const char *path)
{
    void *stream = NULL;
    int64_t size = 0;
    
    mz_stream_os_create(&stream);

    if (mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        mz_stream_os_seek(stream, 0, MZ_STREAM_SEEK_END);
        size = mz_stream_os_tell(stream);
        mz_stream_os_close(stream);
    }

    mz_stream_os_delete(&stream);

    return (size >= UINT32_MAX);
}