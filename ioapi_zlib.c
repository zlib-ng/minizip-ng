/* ioapi_mem.c -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   This version of ioapi is designed to access memory rather than files.
   We do use a region of memory to put data in to and take it out of. We do
   not have auto-extending buffers and do not inform anyone else that the
   data has been written. It is really intended for accessing a zip archive
   embedded in an application such that I can write an installer with no
   external files. Creation of archives has not been attempted, although
   parts of the framework are present.

   Based on Unzip ioapi.c version 0.22, May 19th, 2003

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2003 Justin Fletcher
   Copyright (C) 1998-2003 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This file is under the same license as the Unzip tool it is distributed
   with.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#include "ioapi_zlib.h"

#ifndef DEF_MEM_LEVEL
#  if MAX_MEM_LEVEL >= 8
#    define DEF_MEM_LEVEL 8
#  else
#    define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#  endif
#endif

typedef struct mz_stream_zlib_s {
    mz_stream    stream;
    z_stream    zstream;
    uint8_t     buffer[UINT16_MAX];
    int32_t     buffer_len;
    uint64_t    total_in;
    uint64_t    total_out;
    int8_t      initialized;
    int16_t     level;
    int16_t     window_bits;
    int16_t     mem_level;
    int16_t     strategy;
    int16_t     mode;
    int16_t     error;
} mz_stream_zlib;

int32_t ZCALLBACK mz_stream_zlib_open(voidpf stream, const char *filename, int mode)
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

    if (mode & MZ_STREAM_MODE_READ)
    {
        zlib->zstream.next_in = zlib->buffer;
        zlib->zstream.avail_in = 0;

        zlib->error = inflateInit2(&zlib->zstream, -MAX_WBITS);
    }
    else if (mode & MZ_STREAM_MODE_WRITE)
    {
        window_bits = zlib->window_bits;
        if (window_bits > 0)
            window_bits = -window_bits;

        zlib->zstream.next_out = zlib->buffer;
        zlib->zstream.avail_out = UINT16_MAX;

        zlib->error = deflateInit2(&zlib->zstream, zlib->level, Z_DEFLATED, window_bits, zlib->mem_level, zlib->strategy);
    }

    if (zlib->error != Z_OK)
        return MZ_STREAM_ERR;

    zlib->initialized = 1;
    zlib->mode = mode;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_zlib_is_open(voidpf stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (zlib->initialized != 1)
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_zlib_read(voidpf stream, void *buf, uint32_t size)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint32_t total_out_before = 0;
    uint32_t total_out_after = 0;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;
    int32_t bytes_read = 0;

    zlib->zstream.next_out = (uint8_t*)buf;
    zlib->zstream.avail_out = (uint16_t)size;

    do
    {
        if (zlib->zstream.avail_in == 0)
        {
            bytes_read = mz_stream_read(zlib->stream.base, zlib->buffer, UINT16_MAX);
            if (mz_stream_error(zlib->stream.base))
            {
                zlib->error = Z_STREAM_ERROR;
                break;
            }
            if (bytes_read == 0)
                break;

            zlib->total_in += bytes_read;

            zlib->zstream.next_in = zlib->buffer;
            zlib->zstream.avail_in = bytes_read;
        }

        total_out_before = zlib->zstream.total_out;

        zlib->error = inflate(&zlib->zstream, Z_SYNC_FLUSH);
        if ((zlib->error >= Z_OK) && (zlib->zstream.msg != NULL))
        {
            zlib->error = Z_DATA_ERROR;
            break;
        }

        total_out_after = zlib->zstream.total_out;

        out_bytes = total_out_after - total_out_before;
        total_out += out_bytes;
    }
    while (zlib->zstream.avail_out > 0);

    zlib->total_out += total_out;

    return total_out;
}

int32_t mz_stream_zlib_flush(voidpf stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (mz_stream_write(zlib->stream.base, zlib->buffer, zlib->buffer_len) != zlib->buffer_len)
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

uint32_t mz_stream_zlib_deflate(voidpf stream, int flush)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint32_t total_out_before = 0;
    uint32_t total_out_after = 0;
    uint32_t out_bytes = 0;

    total_out_before = zlib->zstream.total_out;
    zlib->error = deflate(&zlib->zstream, flush);
    total_out_after = zlib->zstream.total_out;

    out_bytes = (uint32_t)(total_out_after - total_out_before);

    return out_bytes;
}

int32_t ZCALLBACK mz_stream_zlib_write(voidpf stream, const void *buf, uint32_t size)
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
            if (mz_stream_zlib_flush(zlib) == MZ_STREAM_ERR)
            {
                zlib->error = Z_STREAM_ERROR;
                return 0;
            }

            zlib->zstream.avail_out = UINT32_MAX;
            zlib->zstream.next_out = zlib->buffer;

            zlib->buffer_len = 0;
        }
        
        out_bytes = mz_stream_zlib_deflate(stream, Z_NO_FLUSH);

        total_out += out_bytes;
        zlib->buffer_len += out_bytes;
    }

    zlib->total_in += size;
    zlib->total_out += total_out;

    return total_out;
}

int64_t ZCALLBACK mz_stream_zlib_tell(voidpf stream)
{
    mz_stream_zlib *mem = (mz_stream_zlib *)stream;
    return MZ_STREAM_ERR;
}

int32_t ZCALLBACK mz_stream_zlib_seek(voidpf stream, uint64_t offset, int origin)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return MZ_STREAM_ERR;
}

int32_t ZCALLBACK mz_stream_zlib_close(voidpf stream)
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
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_zlib_error(voidpf stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->error;
}

void mz_stream_zlib_set_level(voidpf stream, int16_t level)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->level = level;
}

void mz_stream_zlib_set_window_bits(voidpf stream, int16_t window_bits)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->window_bits = window_bits;
}

void mz_stream_zlib_set_mem_level(voidpf stream, int16_t mem_level)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->mem_level = mem_level;
}

void mz_stream_zlib_set_strategy(voidpf stream, int16_t strategy)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    zlib->strategy = strategy;
}

uint64_t mz_stream_zlib_get_total_in(voidpf stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->total_in;
}

uint64_t mz_stream_zlib_get_total_out(voidpf stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    return zlib->total_out;
}

voidpf mz_stream_zlib_create(voidpf *stream)
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
        zlib->level = Z_DEFAULT_COMPRESSION;
        zlib->window_bits = -MAX_WBITS;
        zlib->mem_level = DEF_MEM_LEVEL;
        zlib->strategy = Z_DEFAULT_STRATEGY;
    }
    if (stream != NULL)
        *stream = zlib;

    return (voidpf)zlib;
}

void mz_stream_zlib_delete(voidpf *stream)
{
    mz_stream_zlib *zlib = NULL;
    if (stream == NULL)
        return;
    zlib = (mz_stream_zlib *)*stream;
    if (zlib != NULL)
        free(zlib);
}

typedef struct mz_stream_crc32_s {
    mz_stream    stream;
    int8_t      initialized;
    uint32_t    value;
} mz_stream_crc32;

int32_t ZCALLBACK mz_stream_crc32_open(voidpf stream, const char *filename, int mode)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    crc32->initialized = 1;
    crc32->value = 0;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_crc32_is_open(voidpf stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    if (crc32->initialized != 1)
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_crc32_read(voidpf stream, void *buf, uint32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    int32_t read = mz_stream_read(crc32x->stream.base, buf, size);
    if (read > 0)
        crc32x->value = crc32(crc32x->value, buf, read);
    return read;
}

int32_t ZCALLBACK mz_stream_crc32_write(voidpf stream, const void *buf, uint32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    crc32x->value = crc32(crc32x->value, buf, size);
    return mz_stream_write(crc32x->stream.base, buf, size);
}

int64_t ZCALLBACK mz_stream_crc32_tell(voidpf stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_tell(crc32->stream.base);
}

int32_t ZCALLBACK mz_stream_crc32_seek(voidpf stream, uint64_t offset, int origin)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_seek(crc32->stream.base, offset, origin);
}

int32_t ZCALLBACK mz_stream_crc32_close(voidpf stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    crc32->initialized = 0;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_crc32_error(voidpf stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return mz_stream_error(crc32->stream.base);
}

uint32_t mz_stream_crc32_get_value(voidpf stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return crc32->value;
}

voidpf mz_stream_crc32_create(voidpf *stream)
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
    }
    if (stream != NULL)
        *stream = crc32;

    return (voidpf)crc32;
}

void mz_stream_crc32_delete(voidpf *stream)
{
    mz_stream_crc32 *crc32 = NULL;
    if (stream == NULL)
        return;
    crc32 = (mz_stream_crc32 *)*stream;
    if (crc32 != NULL)
        free(crc32);
}