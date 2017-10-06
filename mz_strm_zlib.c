/* mz_strm_zlib.c -- Stream for zlib inflate/deflate
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "zlib.h"

#include "mz_error.h"
#include "mz_strm.h"
#include "mz_strm_zlib.h"

/***************************************************************************/

#ifndef DEF_MEM_LEVEL
#  if MAX_MEM_LEVEL >= 8
#    define DEF_MEM_LEVEL 8
#  else
#    define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#  endif
#endif

/***************************************************************************/

typedef struct mz_stream_zlib_s {
    mz_stream   stream;
    z_stream    zstream;
    uint8_t     buffer[UINT16_MAX];
    int32_t     buffer_len;
    int64_t     total_in;
    int64_t     total_out;
    int64_t     max_total_in;
    int8_t      initialized;
    int16_t     level;
    int16_t     window_bits;
    int16_t     mem_level;
    int16_t     strategy;
    int16_t     mode;
    int16_t     error;
} mz_stream_zlib;

/***************************************************************************/

int32_t mz_stream_zlib_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    int16_t window_bits = 0;


    zlib->zstream.data_type = Z_BINARY;
    zlib->zstream.zalloc = Z_NULL;
    zlib->zstream.zfree = Z_NULL;
    zlib->zstream.opaque = Z_NULL;
    zlib->zstream.total_in = 0;
    zlib->zstream.total_out = 0;

    zlib->total_in = 0;
    zlib->total_out = 0;

    window_bits = zlib->window_bits;
    if (window_bits > 0)
        window_bits = -window_bits;

    if (mode & MZ_STREAM_MODE_READ)
    {
        zlib->zstream.next_in = zlib->buffer;
        zlib->zstream.avail_in = 0;

        zlib->error = inflateInit2(&zlib->zstream, window_bits);
    }
    else if (mode & MZ_STREAM_MODE_WRITE)
    {
        zlib->zstream.next_out = zlib->buffer;
        zlib->zstream.avail_out = sizeof(zlib->buffer);

        zlib->error = deflateInit2(&zlib->zstream, (int8_t)zlib->level, Z_DEFLATED, window_bits, zlib->mem_level, zlib->strategy);
    }

    if (zlib->error != Z_OK)
        return MZ_STREAM_ERROR;

    zlib->initialized = 1;
    zlib->mode = mode;
    return MZ_OK;
}

int32_t mz_stream_zlib_is_open(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (zlib->initialized != 1)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_zlib_read(void *stream, void *buf, int32_t size)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;
    int32_t bytes_to_read = 0;
    int32_t read = 0;
    int16_t err = Z_OK;


    zlib->zstream.next_out = (uint8_t*)buf;
    zlib->zstream.avail_out = (uint16_t)size;

    do
    {
        if (zlib->zstream.avail_in == 0)
        {
            bytes_to_read = sizeof(zlib->buffer);
            if (zlib->max_total_in > 0)
            {
                if ((zlib->max_total_in - zlib->total_in) < sizeof(zlib->buffer))
                    bytes_to_read = (int32_t)(zlib->max_total_in - zlib->total_in);
            }               
            
            read = mz_stream_read(zlib->stream.base, zlib->buffer, bytes_to_read);

            if (read < 0)
            {
                zlib->error = Z_STREAM_ERROR;
                break;
            }
            if (read == 0)
                break;

            zlib->total_in += read;

            zlib->zstream.next_in = zlib->buffer;
            zlib->zstream.avail_in = read;
        }

        total_out_before = zlib->zstream.total_out;

        err = inflate(&zlib->zstream, Z_SYNC_FLUSH);
        if ((err >= Z_OK) && (zlib->zstream.msg != NULL))
        {
            zlib->error = Z_DATA_ERROR;
            break;
        }

        total_out_after = zlib->zstream.total_out;

        out_bytes = (uint32_t)(total_out_after - total_out_before);
        total_out += out_bytes;

        if (err == Z_STREAM_END)
        {
            break;
        }
        if (err != Z_OK)
        {
            zlib->error = err;
            break;
        }
    }
    while (zlib->zstream.avail_out > 0);

    zlib->total_out += total_out;

    return total_out;
}

int32_t mz_stream_zlib_flush(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (mz_stream_write(zlib->stream.base, zlib->buffer, zlib->buffer_len) != zlib->buffer_len)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

uint32_t mz_stream_zlib_deflate(void *stream, int flush)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    int16_t err = Z_OK;

    total_out_before = zlib->zstream.total_out;
    err = deflate(&zlib->zstream, flush);
    total_out_after = zlib->zstream.total_out;

    out_bytes = (uint32_t)(total_out_after - total_out_before);

    if (err != Z_OK && err != Z_STREAM_END)
    {
        zlib->error = err;
        return MZ_STREAM_ERROR;
    }

    return out_bytes;
}

int32_t mz_stream_zlib_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;


    zlib->zstream.next_in = (uint8_t*)buf;
    zlib->zstream.avail_in = size;

    while ((zlib->error == Z_OK) && (zlib->zstream.avail_in > 0))
    {
        if (zlib->zstream.avail_out == 0)
        {
            if (mz_stream_zlib_flush(zlib) != MZ_OK)
            {
                zlib->error = Z_STREAM_ERROR;
                return 0;
            }

            zlib->zstream.avail_out = sizeof(zlib->buffer);
            zlib->zstream.next_out = zlib->buffer;

            zlib->buffer_len = 0;
        }
        
        out_bytes = mz_stream_zlib_deflate(stream, Z_NO_FLUSH);

        total_out += out_bytes;
        zlib->buffer_len += out_bytes;
    }

    zlib->total_in += size;
    zlib->total_out += total_out;

    return size;
}

int64_t mz_stream_zlib_tell(void *stream)
{
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_zlib_seek(void *stream, int64_t offset, int32_t origin)
{
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_zlib_close(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint32_t out_bytes = 0;

    if (zlib->mode & MZ_STREAM_MODE_READ)
    {
        inflateEnd(&zlib->zstream);
    }
    else if (zlib->mode & MZ_STREAM_MODE_WRITE)
    {
        out_bytes = mz_stream_zlib_deflate(stream, Z_FINISH);

        zlib->buffer_len += out_bytes;
        zlib->total_out += out_bytes;

        mz_stream_zlib_flush(stream);

        zlib->error = deflateEnd(&zlib->zstream);
    }

    zlib->initialized = 0;

    if (zlib->error != Z_OK)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_zlib_error(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->error;
}

void mz_stream_zlib_set_level(void *stream, int16_t level)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->level = level;
}

void mz_stream_zlib_set_window_bits(void *stream, int16_t window_bits)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (window_bits == 0)
        window_bits = -MAX_WBITS;
    zlib->window_bits = window_bits;
}

void mz_stream_zlib_set_mem_level(void *stream, int16_t mem_level)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (mem_level == 0)
        mem_level = DEF_MEM_LEVEL;
    zlib->mem_level = mem_level;
}

void mz_stream_zlib_set_strategy(void *stream, int16_t strategy)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->strategy = strategy;
}

int64_t mz_stream_zlib_get_total_in(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->total_in;
}

int64_t mz_stream_zlib_get_total_out(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->total_out;
}

void mz_stream_zlib_set_max_total_in(void *stream, int64_t max_total_in)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->max_total_in = max_total_in;
}

void *mz_stream_zlib_create(void **stream)
{
    mz_stream_zlib *zlib = NULL;

    zlib = (mz_stream_zlib *)malloc(sizeof(mz_stream_zlib));
    if (zlib != NULL)
    {
        memset(zlib, 0, sizeof(mz_stream_zlib));

        zlib->stream.open = mz_stream_zlib_open;
        zlib->stream.is_open = mz_stream_zlib_is_open;
        zlib->stream.read = mz_stream_zlib_read;
        zlib->stream.write = mz_stream_zlib_write;
        zlib->stream.tell = mz_stream_zlib_tell;
        zlib->stream.seek = mz_stream_zlib_seek;
        zlib->stream.close = mz_stream_zlib_close;
        zlib->stream.error = mz_stream_zlib_error;
        zlib->stream.create = mz_stream_zlib_create;
        zlib->stream.delete = mz_stream_zlib_delete;
        zlib->stream.get_total_in = mz_stream_zlib_get_total_in;
        zlib->stream.get_total_out = mz_stream_zlib_get_total_out;
        zlib->level = Z_DEFAULT_COMPRESSION;
        zlib->window_bits = -MAX_WBITS;
        zlib->mem_level = DEF_MEM_LEVEL;
        zlib->strategy = Z_DEFAULT_STRATEGY;
    }
    if (stream != NULL)
        *stream = zlib;

    return zlib;
}

void mz_stream_zlib_delete(void **stream)
{
    mz_stream_zlib *zlib = NULL;
    if (stream == NULL)
        return;
    zlib = (mz_stream_zlib *)*stream;
    if (zlib != NULL)
        free(zlib);
    *stream = NULL;
}

/***************************************************************************/

typedef struct mz_stream_crc32_s {
    mz_stream  stream;
    int8_t     initialized;
    int32_t    value;
    int64_t    total_in;
    int64_t    total_out;
} mz_stream_crc32;

/***************************************************************************/

int32_t mz_stream_crc32_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    crc32->initialized = 1;
    crc32->value = 0;
    return MZ_OK;
}

int32_t mz_stream_crc32_is_open(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    if (crc32->initialized != 1)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_crc32_read(void *stream, void *buf, int32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    int32_t read = mz_stream_read(crc32x->stream.base, buf, size);
    if (read > 0)
        crc32x->value = (int32_t)crc32(crc32x->value, buf, read);
    crc32x->total_in += read;
    return read;
}

int32_t mz_stream_crc32_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    int32_t written = 0;
    crc32x->value = (int32_t)crc32(crc32x->value, buf, size);
    written = mz_stream_write(crc32x->stream.base, buf, size);
    crc32x->total_out += written;
    return written;
}

int64_t mz_stream_crc32_tell(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_tell(crc32->stream.base);
}

int32_t mz_stream_crc32_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_seek(crc32->stream.base, offset, origin);
}

int32_t mz_stream_crc32_close(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    crc32->initialized = 0;
    return MZ_OK;
}

int32_t mz_stream_crc32_error(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_error(crc32->stream.base);
}

int32_t mz_stream_crc32_get_value(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return crc32->value;
}

int64_t mz_stream_crc32_get_total_in(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return crc32->total_in;
}

int64_t mz_stream_crc32_get_total_out(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return crc32->total_out;
}

void *mz_stream_crc32_create(void **stream)
{
    mz_stream_crc32 *crc32 = NULL;

    crc32 = (mz_stream_crc32 *)malloc(sizeof(mz_stream_crc32));
    if (crc32 != NULL)
    {
        memset(crc32, 0, sizeof(mz_stream_crc32));

        crc32->stream.open = mz_stream_crc32_open;
        crc32->stream.is_open = mz_stream_crc32_is_open;
        crc32->stream.read = mz_stream_crc32_read;
        crc32->stream.write = mz_stream_crc32_write;
        crc32->stream.tell = mz_stream_crc32_tell;
        crc32->stream.seek = mz_stream_crc32_seek;
        crc32->stream.close = mz_stream_crc32_close;
        crc32->stream.error = mz_stream_crc32_error;
        crc32->stream.create = mz_stream_crc32_create;
        crc32->stream.delete = mz_stream_crc32_delete;
        crc32->stream.get_total_in = mz_stream_crc32_get_total_in;
        crc32->stream.get_total_out = mz_stream_crc32_get_total_out;
    }
    if (stream != NULL)
        *stream = crc32;

    return crc32;
}

void mz_stream_crc32_delete(void **stream)
{
    mz_stream_crc32 *crc32 = NULL;
    if (stream == NULL)
        return;
    crc32 = (mz_stream_crc32 *)*stream;
    if (crc32 != NULL)
        free(crc32);
    *stream = NULL;
}
