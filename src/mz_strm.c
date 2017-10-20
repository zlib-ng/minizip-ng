/* mz_strm.c -- Stream interface
   Version 2.1.0, October 20th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <time.h>

#include "mz.h"
#include "mz_strm.h"

/***************************************************************************/

int32_t mz_stream_open(void *stream, const char *path, int32_t mode)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->open == NULL)
        return MZ_STREAM_ERROR;
    return strm->vtbl->open(strm, path, mode);
}

int32_t mz_stream_is_open(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->is_open == NULL)
        return MZ_STREAM_ERROR;
    return strm->vtbl->is_open(strm);
}

int32_t mz_stream_read(void *stream, void *buf, int32_t size)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->read == NULL)
        return MZ_PARAM_ERROR;
    if (mz_stream_is_open(stream) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->vtbl->read(strm, buf, size);
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
    if (size == 0)
        return size;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->write == NULL)
        return MZ_PARAM_ERROR;
    if (mz_stream_is_open(stream) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->vtbl->write(strm, buf, size);
}

static int32_t mz_stream_write_value(void *stream, uint64_t value, int32_t len)
{
    uint8_t buf[8];
    int32_t n = 0;

    for (n = 0; n < len; n += 1)
    {
        buf[n] = (uint8_t)(value & 0xff);
        value >>= 8;
    }

    if (value != 0)
    {
        // Data overflow - hack for ZIP64 (X Roche)
        for (n = 0; n < len; n += 1)
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
    uint8_t buf[INT16_MAX];
    int32_t bytes_to_copy = 0;
    int32_t read = 0;
    int32_t written = 0;

    while (len > 0)
    {
        bytes_to_copy = len;
        if (bytes_to_copy > sizeof(buf))
            bytes_to_copy = sizeof(buf);
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
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->tell == NULL)
        return MZ_PARAM_ERROR;
    if (mz_stream_is_open(stream) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->vtbl->tell(strm);
}

int32_t mz_stream_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->seek == NULL)
        return MZ_PARAM_ERROR;
    if (mz_stream_is_open(stream) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->vtbl->seek(strm, offset, origin);
}

int32_t mz_stream_close(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->close == NULL)
        return MZ_PARAM_ERROR;
    if (mz_stream_is_open(stream) != MZ_OK)
        return MZ_STREAM_ERROR;
    return strm->vtbl->close(strm);
}

int32_t mz_stream_error(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->error == NULL)
        return MZ_PARAM_ERROR;
    return strm->vtbl->error(strm);
}

int32_t mz_stream_set_base(void *stream, void *base)
{
    mz_stream *strm = (mz_stream *)stream;
    strm->base = (mz_stream *)base;
    return MZ_OK;
}

int32_t mz_stream_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->get_prop_int64 == NULL)
        return MZ_PARAM_ERROR;
    return strm->vtbl->get_prop_int64(stream, prop, value);
}

int32_t mz_stream_set_prop_int64(void *stream, int32_t prop, int64_t value)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL || strm->vtbl->set_prop_int64 == NULL)
        return MZ_PARAM_ERROR;
    return strm->vtbl->set_prop_int64(stream, prop, value);
}

void *mz_stream_create(void **stream, mz_stream_vtbl *vtbl)
{
    if (stream == NULL)
        return NULL;
    if (vtbl == NULL || vtbl->create == NULL)
        return NULL;
    return vtbl->create(stream);
}

void mz_stream_delete(void **stream)
{
    mz_stream *strm = NULL;
    if (stream == NULL)
        return;
    strm = (mz_stream *)*stream;
    if (strm != NULL && strm->vtbl != NULL && strm->vtbl->delete != NULL)
        strm->vtbl->delete(stream);
    *stream = NULL;
}
