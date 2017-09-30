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

typedef struct mzstream_zlib_s {
    mzstream    stream;
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
} mzstream_zlib;

int32_t ZCALLBACK mzstream_zlib_open(voidpf stream, const char *filename, int mode)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    int16_t window_bits = 0;


    zlib->zstream.data_type = Z_BINARY;
    zlib->zstream.zalloc = Z_NULL;
    zlib->zstream.zfree = Z_NULL;
    zlib->zstream.opaque = Z_NULL;
    zlib->zstream.total_in = 0;
    zlib->zstream.total_out = 0;

    zlib->total_in = 0;
    zlib->total_out = 0;

    if (mode == MZSTREAM_MODE_READ)
    {
        zlib->zstream.next_in = zlib->buffer;
        zlib->zstream.avail_in = 0;

        zlib->error = inflateInit2(&zlib->zstream, -MAX_WBITS);
    }
    else if (mode == MZSTREAM_MODE_WRITE)
    {
        window_bits = zlib->window_bits;
        if (window_bits > 0)
            window_bits = -window_bits;

        zlib->zstream.next_out = zlib->buffer;
        zlib->zstream.avail_out = UINT16_MAX;

        zlib->error = deflateInit2(&zlib->zstream, zlib->level, Z_DEFLATED, window_bits, zlib->mem_level, zlib->strategy);
    }

    if (zlib->error != Z_OK)
        return MZSTREAM_ERR;

    zlib->initialized = 1;
    zlib->mode = mode;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_zlib_is_open(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    if (zlib->initialized != 1)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_zlib_read(voidpf stream, void *buf, uint32_t size)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
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
            bytes_read = mzstream_read(zlib->stream.base, zlib->buffer, UINT16_MAX);
            if (mzstream_error(zlib->stream.base))
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

int32_t mzstream_zlib_flush(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    if (mzstream_write(zlib->stream.base, zlib->buffer, zlib->buffer_len) != zlib->buffer_len)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

uint32_t mzstream_zlib_deflate(voidpf stream, int flush)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    uint32_t total_out_before = 0;
    uint32_t total_out_after = 0;
    uint32_t out_bytes = 0;

    total_out_before = zlib->zstream.total_out;
    zlib->error = deflate(&zlib->zstream, flush);
    total_out_after = zlib->zstream.total_out;

    out_bytes = (uint32_t)(total_out_after - total_out_before);

    return out_bytes;
}

int32_t ZCALLBACK mzstream_zlib_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;


    zlib->zstream.next_in = (uint8_t*)buf;
    zlib->zstream.avail_in = size;

    while ((zlib->error == Z_OK) && (zlib->zstream.avail_in > 0))
    {
        if (zlib->zstream.avail_out == 0)
        {
            if (mzstream_zlib_flush(zlib) == MZSTREAM_ERR)
            {
                zlib->error = Z_STREAM_ERROR;
                return 0;
            }

            zlib->zstream.avail_out = UINT32_MAX;
            zlib->zstream.next_out = zlib->buffer;

            zlib->buffer_len = 0;
        }
        
        out_bytes = mzstream_zlib_deflate(stream, Z_NO_FLUSH);

        total_out += out_bytes;
        zlib->buffer_len += out_bytes;
    }

    zlib->total_in += size;
    zlib->total_out += total_out;

    return total_out;
}

int64_t ZCALLBACK mzstream_zlib_tell(voidpf stream)
{
    mzstream_zlib *mem = (mzstream_zlib *)stream;
    return MZSTREAM_ERR;
}

int32_t ZCALLBACK mzstream_zlib_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    return MZSTREAM_ERR;
}

int32_t ZCALLBACK mzstream_zlib_close(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    uint32_t out_bytes = 0;

    if (zlib->mode == MZSTREAM_MODE_READ)
    {
        inflateEnd(&zlib->zstream);
    }
    else if (zlib->mode == MZSTREAM_MODE_WRITE)
    {
        out_bytes = mzstream_zlib_deflate(stream, Z_FINISH);

        zlib->buffer_len += out_bytes;
        zlib->total_out += out_bytes;

        mzstream_zlib_flush(stream);

        zlib->error = deflateEnd(&zlib->zstream);
    }

    zlib->initialized = 0;
    if (zlib->error != Z_OK)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_zlib_error(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    return zlib->error;
}

void mzstream_zlib_set_level(voidpf stream, int16_t level)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    zlib->level = level;
}

void mzstream_zlib_set_window_bits(voidpf stream, int16_t window_bits)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    zlib->window_bits = window_bits;
}

void mzstream_zlib_set_mem_level(voidpf stream, int16_t mem_level)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    zlib->mem_level = mem_level;
}

void mzstream_zlib_set_strategy(voidpf stream, int16_t strategy)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    zlib->strategy = strategy;
}

uint64_t mzstream_zlib_get_total_in(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    return zlib->total_in;
}

uint64_t mzstream_zlib_get_total_out(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    return zlib->total_out;
}

voidpf mzstream_zlib_alloc(void)
{
    mzstream_zlib *zlib = NULL;

    zlib = (mzstream_zlib *)malloc(sizeof(mzstream_zlib));
    if (zlib == NULL)
        return NULL;

    memset(zlib, 0, sizeof(mzstream_zlib));

    zlib->stream.open = mzstream_zlib_open;
    zlib->stream.is_open = mzstream_zlib_is_open;
    zlib->stream.read = mzstream_zlib_read;
    zlib->stream.write = mzstream_zlib_write;
    zlib->stream.tell = mzstream_zlib_tell;
    zlib->stream.seek = mzstream_zlib_seek;
    zlib->stream.close = mzstream_zlib_close;
    zlib->stream.error = mzstream_zlib_error;
    zlib->stream.alloc = mzstream_zlib_alloc;
    zlib->stream.free = mzstream_zlib_free;
    zlib->level = Z_DEFAULT_COMPRESSION;
    zlib->window_bits = -MAX_WBITS;
    zlib->mem_level = DEF_MEM_LEVEL;
    zlib->strategy = Z_DEFAULT_STRATEGY;

    return (voidpf)zlib;
}

void mzstream_zlib_free(voidpf stream)
{
    mzstream_zlib *zlib = (mzstream_zlib *)stream;
    if (zlib != NULL)
        free(zlib);
}

typedef struct mzstream_crc32_s {
    mzstream    stream;
    int8_t      initialized;
    uint32_t    value;
} mzstream_crc32;

int32_t ZCALLBACK mzstream_crc32_open(voidpf stream, const char *filename, int mode)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    crc32->initialized = 1;
    crc32->value = 0;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crc32_is_open(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    if (crc32->initialized != 1)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crc32_read(voidpf stream, void *buf, uint32_t size)
{
    mzstream_crc32 *crc32x = (mzstream_crc32 *)stream;
    int32_t read = mzstream_read(crc32x->stream.base, buf, size);
    if (read > 0)
        crc32x->value = crc32(crc32x->value, buf, read);
    return read;
}

int32_t ZCALLBACK mzstream_crc32_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_crc32 *crc32x = (mzstream_crc32 *)stream;
    crc32x->value = crc32(crc32x->value, buf, size);
    return mzstream_write(crc32x->stream.base, buf, size);
}

int64_t ZCALLBACK mzstream_crc32_tell(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    return mzstream_tell(crc32->stream.base);
}

int32_t ZCALLBACK mzstream_crc32_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    return MZSTREAM_ERR;
}

int32_t ZCALLBACK mzstream_crc32_close(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    crc32->initialized = 0;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crc32_error(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    return mzstream_error(crc32->stream.base);
}

uint32_t mzstream_crc32_get_value(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    return crc32->value;
}

voidpf mzstream_crc32_alloc(void)
{
    mzstream_crc32 *crc32 = NULL;

    crc32 = (mzstream_crc32 *)malloc(sizeof(mzstream_crc32));
    if (crc32 == NULL)
        return NULL;

    memset(crc32, 0, sizeof(mzstream_crc32));

    crc32->stream.open = mzstream_crc32_open;
    crc32->stream.is_open = mzstream_crc32_is_open;
    crc32->stream.read = mzstream_crc32_read;
    crc32->stream.write = mzstream_crc32_write;
    crc32->stream.tell = mzstream_crc32_tell;
    crc32->stream.seek = mzstream_crc32_seek;
    crc32->stream.close = mzstream_crc32_close;
    crc32->stream.error = mzstream_crc32_error;
    crc32->stream.alloc = mzstream_crc32_alloc;
    crc32->stream.free = mzstream_crc32_free;

    return (voidpf)crc32;
}

void mzstream_crc32_free(voidpf stream)
{
    mzstream_crc32 *crc32 = (mzstream_crc32 *)stream;
    if (crc32 != NULL)
        free(crc32);
}