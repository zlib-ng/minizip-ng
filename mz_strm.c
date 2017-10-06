/* mz_strm.c -- Stream interface
   Version 2.0.0, October 4th, 2017
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

#include <time.h>

#include "mz_error.h"
#include "mz_strm.h"

/***************************************************************************/

int32_t mz_stream_open(void *stream, const char *path, int32_t mode)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->open == NULL)
        return MZ_STREAM_ERROR;
    return strm->open(strm, path, mode);
}

int32_t mz_stream_is_open(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->is_open == NULL)
        return MZ_STREAM_ERROR;
    return strm->is_open(strm);
}

int32_t mz_stream_read(void *stream, void *buf, int32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->read == NULL)
        return MZ_STREAM_ERROR;
    if (strm->is_open != NULL && strm->is_open(strm) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->read(strm, buf, size);
}

int32_t mz_stream_read_uint8(void *stream, uint8_t *value)
{
    uint8_t c = 0;
    
    if (mz_stream_read(stream, &c, 1) == 1)
        *value = (uint8_t)c;
    else if (mz_stream_error(stream))
        return MZ_STREAM_ERROR;

    return MZ_OK;
}

int32_t mz_stream_read_uint16(void *stream, uint16_t *value)
{
    uint8_t c = 0;

    *value = 0;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value = (uint16_t)c;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint16_t)c) << 8;

    return MZ_OK;
}

int32_t mz_stream_read_uint32(void *stream, uint32_t *value)
{
    uint8_t c = 0;

    *value = 0;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value = (uint32_t)c;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint32_t)c) << 8;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint32_t)c) << 16;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint32_t)c) << 24;

    return MZ_OK;
}

int32_t mz_stream_read_uint64(void *stream, uint64_t *value)
{
    uint8_t c = 0;

    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value = (uint64_t)c;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 8;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 16;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 24;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 32;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 40;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 48;
    if (mz_stream_read_uint8(stream, &c) != MZ_OK)
        return MZ_STREAM_ERROR;
    *value += ((uint64_t)c) << 56;

    return MZ_OK;
}

int32_t mz_stream_write(void *stream, const void *buf, int32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->write == NULL)
        return MZ_STREAM_ERROR;
    if (size == 0)
        return size;
    if (strm->is_open != NULL && strm->is_open(strm) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->write(strm, buf, size);
}

static int32_t mz_stream_write_value(void *stream, uint64_t value, uint32_t len)
{
    uint8_t buf[8];
    uint32_t n = 0;

    for (n = 0; n < len; n++)
    {
        buf[n] = (uint8_t)(value & 0xff);
        value >>= 8;
    }

    if (value != 0)
    {
        // Data overflow - hack for ZIP64 (X Roche)
        for (n = 0; n < len; n++)
            buf[n] = 0xff;
    }

    if (mz_stream_write(stream, buf, len) != len)
        return MZ_STREAM_ERROR;

    return MZ_OK;
}

int32_t mz_stream_write_uint8(void *stream, uint8_t value)
{
    return mz_stream_write_value(stream, value, sizeof(uint8_t));
}

int32_t mz_stream_write_uint16(void *stream, uint16_t value)
{
    return mz_stream_write_value(stream, value, sizeof(uint16_t));
}

int32_t mz_stream_write_uint32(void *stream, uint32_t value)
{
    return mz_stream_write_value(stream, value, sizeof(uint32_t));
}

int32_t mz_stream_write_uint64(void *stream, uint64_t value)
{
    return mz_stream_write_value(stream, value, sizeof(uint64_t));
}

int32_t mz_stream_copy(void *target, void *source, int32_t len)
{
    uint8_t buf[UINT16_MAX];
    int32_t bytes_to_copy = 0;
    int32_t read = 0;
    int32_t written = 0;

    while (len > 0)
    {
        bytes_to_copy = len;
        if (bytes_to_copy > UINT16_MAX)
            bytes_to_copy = UINT16_MAX;
        read = mz_stream_read(source, buf, bytes_to_copy);
        if (read < 0)
            return MZ_STREAM_ERROR;
        written = mz_stream_write(target, buf, read);
        if (written != read)
            return MZ_STREAM_ERROR;
        len -= read;
    }

    return MZ_OK;
}

int64_t mz_stream_tell(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->tell == NULL)
        return MZ_STREAM_ERROR;
    if (strm->is_open != NULL && strm->is_open(strm) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->tell(strm);
}

int32_t mz_stream_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->seek == NULL)
        return MZ_STREAM_ERROR;
    if (strm->is_open != NULL && strm->is_open(strm) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->seek(strm, offset, origin);
}

int32_t mz_stream_close(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->close == NULL)
        return MZ_STREAM_ERROR;
    return strm->close(strm);
}

int32_t mz_stream_error(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->error == NULL)
        return MZ_STREAM_ERROR;
    return strm->error(strm);
}

int32_t mz_stream_set_base(void *stream, void *base)
{
    mz_stream *strm = (mz_stream *)stream;
    strm->base = (mz_stream *)base;
    return MZ_OK;
}

int64_t mz_stream_get_total_in(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm->get_total_in == NULL)
        return MZ_STREAM_ERROR;
    return strm->get_total_in(stream);
}

int64_t mz_stream_get_total_out(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm->get_total_out == NULL)
        return MZ_STREAM_ERROR;
    return strm->get_total_out(stream);
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
    *stream = NULL;
}

/***************************************************************************/

typedef struct mz_stream_passthru_s {
    mz_stream   stream;
    int64_t     total_in;
    int64_t     total_out;
} mz_stream_passthru;

/***************************************************************************/

int32_t mz_stream_passthru_open(void *stream, const char *path, int32_t mode)
{
    return MZ_OK;
}

int32_t mz_stream_passthru_is_open(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_is_open(passthru->stream.base);
}

int32_t mz_stream_passthru_read(void *stream, void *buf, int32_t size)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    int32_t read = mz_stream_read(passthru->stream.base, buf, size);
    if (read > 0)
        passthru->total_in += read;
    return read;
}

int32_t mz_stream_passthru_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    int32_t written = mz_stream_write(passthru->stream.base, buf, size);
    if (written > 0)
        passthru->total_out += written;
    return written;
}

int64_t mz_stream_passthru_tell(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_tell(passthru->stream.base);
}

int32_t mz_stream_passthru_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_seek(passthru->stream.base, offset, origin);
}

int32_t mz_stream_passthru_close(void *stream)
{
    return MZ_OK;
}

int32_t mz_stream_passthru_error(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return mz_stream_error(passthru->stream.base);
}

int64_t mz_stream_passthru_get_total_in(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return passthru->total_in;
}

int64_t mz_stream_passthru_get_total_out(void *stream)
{
    mz_stream_passthru *passthru = (mz_stream_passthru *)stream;
    return passthru->total_out;
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
        passthru->stream.get_total_in = mz_stream_passthru_get_total_in;
        passthru->stream.get_total_out = mz_stream_passthru_get_total_out;
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
    *stream = NULL;
}
