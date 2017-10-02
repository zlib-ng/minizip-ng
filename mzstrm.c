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
#include <string.h>

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
    if (strm->is_open != NULL && strm->is_open(strm) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    return strm->read(strm, buf, size);
}

int32_t mz_stream_read_uint8(void *stream, uint8_t *value)
{
    uint8_t c = 0;
    
    if (mz_stream_read(stream, &c, 1) == 1)
        *value = (uint8_t)c;
    else if (mz_stream_error(stream))
        return MZ_STREAM_ERR;

    return MZ_STREAM_OK;
}

int32_t mz_stream_read_uint16(void *stream, uint16_t *value)
{
    uint8_t c = 0;

    *value = 0;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value = (uint16_t)c;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint16_t)c) << 8;

    return MZ_STREAM_OK;
}

int32_t mz_stream_read_uint32(void *stream, uint32_t *value)
{
    uint8_t c = 0;

    *value = 0;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value = (uint32_t)c;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint32_t)c) << 8;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint32_t)c) << 16;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint32_t)c) << 24;

    return MZ_STREAM_OK;
}

int32_t mz_stream_read_uint64(void *stream, uint64_t *value)
{
    uint8_t c = 0;

    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value = (uint64_t)c;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 8;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 16;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 24;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 32;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 40;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 48;
    if (mz_stream_read_uint8(stream, &c) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    *value += ((uint64_t)c) << 56;

    return MZ_STREAM_OK;
}

int32_t mz_stream_write(void *stream, const void *buf, uint32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->write == NULL)
        return MZ_STREAM_ERR;
    if (strm->is_open != NULL && strm->is_open(strm) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    return strm->write(strm, buf, size);
}

int64_t mz_stream_tell(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->tell == NULL)
        return MZ_STREAM_ERR;
    if (strm->is_open != NULL && strm->is_open(strm) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    return strm->tell(strm);
}

int32_t mz_stream_seek(void *stream, uint64_t offset, int origin)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->seek == NULL)
        return MZ_STREAM_ERR;
    if (strm->is_open != NULL && strm->is_open(strm) == MZ_STREAM_ERR)
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

void *mz_stream_create(void **stream)
{
    mz_stream *strm = NULL;
    if (stream == NULL)
        return NULL;
    strm = (mz_stream *)*stream;
    return strm->create(stream);
}

void mz_stream_delete(void **stream)
{
    mz_stream *strm = NULL;
    if (stream == NULL)
        return;
    strm = (mz_stream *)*stream;
    strm->delete(stream);
}

typedef struct mz_stream_passthru_s {
  mz_stream stream;
} mz_stream_passthru;

int32_t mz_stream_passthru_open(void *stream, const char *path, int mode)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_open(passthru->stream.base, path, mode);
}

int32_t mz_stream_passthru_is_open(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_is_open(passthru->stream.base);
}

int32_t mz_stream_passthru_read(void *stream, void *buf, uint32_t size)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_read(passthru->stream.base, buf, size);
}

int32_t mz_stream_passthru_write(void *stream, const void *buf, uint32_t size)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_write(passthru->stream.base, buf, size);
}

int64_t mz_stream_passthru_tell(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_tell(passthru->stream.base);
}

int32_t mz_stream_passthru_seek(void *stream, uint64_t offset, int origin)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_seek(passthru->stream.base, offset, origin);
}

int32_t mz_stream_passthru_close(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_close(passthru->stream.base);
}

int32_t mz_stream_passthru_error(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_error(passthru->stream.error);
}

void *mz_stream_passthru_create(void **stream)
{
    mz_stream_passthru *passthru = NULL;

    passthru = (mz_stream_passthru *)malloc(sizeof(mz_stream_passthru));
    if (passthru != NULL)
    {
        memset(passthru, 0, sizeof(mz_stream_passthru));

        passthru->stream.open = mz_stream_passthru_open;
        passthru->stream.is_open = mz_stream_passthru_is_open;
        passthru->stream.read = mz_stream_passthru_read;
        passthru->stream.write = mz_stream_passthru_write;
        passthru->stream.tell = mz_stream_passthru_tell;
        passthru->stream.seek = mz_stream_passthru_seek;
        passthru->stream.close = mz_stream_passthru_close;
        passthru->stream.error = mz_stream_passthru_error;
        passthru->stream.create = mz_stream_passthru_create;
        passthru->stream.delete = mz_stream_passthru_delete;
    }
    if (stream != NULL)
        *stream = passthru;

    return passthru;
}

void mz_stream_passthru_delete(void **stream)
{
    mz_stream_passthru *passthru = NULL;
    if (stream == NULL)
        return;
    passthru = (mz_stream_passthru *)*stream;
    if (passthru != NULL)
        free(passthru);
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