/* mz_strm_zlib.c -- Stream for zlib inflate/deflate
   Version 2.2.2, October 26th, 2017
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

#include "mz.h"
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

mz_stream_vtbl mz_stream_zlib_vtbl = {
    mz_stream_zlib_open,
    mz_stream_zlib_is_open,
    mz_stream_zlib_read,
    mz_stream_zlib_write,
    mz_stream_zlib_tell,
    mz_stream_zlib_seek,
    mz_stream_zlib_close,
    mz_stream_zlib_error,
    mz_stream_zlib_create,
    mz_stream_zlib_delete,
    mz_stream_zlib_get_prop_int64,
    mz_stream_zlib_set_prop_int64
};

/***************************************************************************/

typedef struct mz_stream_zlib_s {
    mz_stream   stream;
    z_stream    zstream;
    uint8_t     buffer[INT16_MAX];
    int32_t     buffer_len;
    int64_t     total_in;
    int64_t     total_out;
    int64_t     max_total_in;
    int8_t      initialized;
    int16_t     level;
    int32_t     mode;
    int32_t     error;
} mz_stream_zlib;

/***************************************************************************/

int32_t mz_stream_zlib_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;


    zlib->zstream.data_type = Z_BINARY;
    zlib->zstream.zalloc = Z_NULL;
    zlib->zstream.zfree = Z_NULL;
    zlib->zstream.opaque = Z_NULL;
    zlib->zstream.total_in = 0;
    zlib->zstream.total_out = 0;

    zlib->total_in = 0;
    zlib->total_out = 0;

    if (mode & MZ_OPEN_MODE_WRITE)
    {
        zlib->zstream.next_out = zlib->buffer;
        zlib->zstream.avail_out = sizeof(zlib->buffer);

        zlib->error = deflateInit2(&zlib->zstream, (int8_t)zlib->level, Z_DEFLATED, -MAX_WBITS, DEF_MEM_LEVEL, Z_DEFAULT_STRATEGY);
    }
    else if (mode & MZ_OPEN_MODE_READ)
    {
        zlib->zstream.next_in = zlib->buffer;
        zlib->zstream.avail_in = 0;

        zlib->error = inflateInit2(&zlib->zstream, -MAX_WBITS);
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
    uint64_t total_in_before = 0;
    uint64_t total_in_after = 0;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t total_in = 0;
    uint32_t total_out = 0;
    uint32_t in_bytes = 0;
    uint32_t out_bytes = 0;
    int32_t bytes_to_read = 0;
    int32_t read = 0;
    int32_t err = Z_OK;


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

            zlib->zstream.next_in = zlib->buffer;
            zlib->zstream.avail_in = read;
        }

        total_in_before = zlib->zstream.avail_in;
        total_out_before = zlib->zstream.total_out;

        err = inflate(&zlib->zstream, Z_SYNC_FLUSH);
        if ((err >= Z_OK) && (zlib->zstream.msg != NULL))
        {
            zlib->error = Z_DATA_ERROR;
            break;
        }

        total_in_after = zlib->zstream.avail_in;
        total_out_after = zlib->zstream.total_out;

        in_bytes = (uint32_t)(total_in_before - total_in_after);
        out_bytes = (uint32_t)(total_out_after - total_out_before);

        total_in += in_bytes;
        total_out += out_bytes;

        zlib->total_in += in_bytes;
        zlib->total_out += out_bytes;

        if (err == Z_STREAM_END)
            break;
 
        if (err != Z_OK)
        {
            zlib->error = err;
            break;
        }
    }
    while (zlib->zstream.avail_out > 0);

    if (zlib->error != 0)
        return zlib->error;

    return total_out;
}

int32_t mz_stream_zlib_flush(void *stream)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    if (mz_stream_write(zlib->stream.base, zlib->buffer, zlib->buffer_len) != zlib->buffer_len)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_zlib_deflate(void *stream, int flush)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    int32_t out_bytes = 0;
    int32_t err = Z_OK;


    do
    {
        if (zlib->zstream.avail_out == 0)
        {
            if (mz_stream_zlib_flush(zlib) != MZ_OK)
            {
                zlib->error = Z_STREAM_ERROR;
                return MZ_STREAM_ERROR;
            }

            zlib->zstream.avail_out = sizeof(zlib->buffer);
            zlib->zstream.next_out = zlib->buffer;

            zlib->buffer_len = 0;
        }

        total_out_before = zlib->zstream.total_out;
        err = deflate(&zlib->zstream, flush);
        total_out_after = zlib->zstream.total_out;

        out_bytes = (uint32_t)(total_out_after - total_out_before);

        if (err != Z_OK && err != Z_STREAM_END)
        {
            zlib->error = err;
            return MZ_STREAM_ERROR;
        }

        zlib->buffer_len += out_bytes;
        zlib->total_out += out_bytes;
    }
    while (zlib->zstream.avail_in > 0);

    return MZ_OK;
}

int32_t mz_stream_zlib_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;


    zlib->zstream.next_in = (uint8_t*)buf;
    zlib->zstream.avail_in = size;

    mz_stream_zlib_deflate(stream, Z_NO_FLUSH);

    zlib->total_in += size;

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


    if (zlib->mode & MZ_OPEN_MODE_WRITE)
    {
        mz_stream_zlib_deflate(stream, Z_FINISH);
        mz_stream_zlib_flush(stream);

        deflateEnd(&zlib->zstream);
    }
    else if (zlib->mode & MZ_OPEN_MODE_READ)
    {
        inflateEnd(&zlib->zstream);
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

int32_t mz_stream_zlib_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = zlib->total_in;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = zlib->total_out;
        return MZ_OK;
    case MZ_STREAM_PROP_HEADER_SIZE:
        *value = 0;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

int32_t mz_stream_zlib_set_prop_int64(void *stream, int32_t prop, int64_t value)
{
    mz_stream_zlib *zlib = (mz_stream_zlib *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_COMPRESS_LEVEL:
        zlib->level = (int16_t)value;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        zlib->max_total_in = value;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

void *mz_stream_zlib_create(void **stream)
{
    mz_stream_zlib *zlib = NULL;

    zlib = (mz_stream_zlib *)malloc(sizeof(mz_stream_zlib));
    if (zlib != NULL)
    {
        memset(zlib, 0, sizeof(mz_stream_zlib));
        zlib->stream.vtbl = &mz_stream_zlib_vtbl;
        zlib->level = Z_DEFAULT_COMPRESSION;
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

void *mz_stream_zlib_get_interface(void)
{
    return (void *)&mz_stream_zlib_vtbl;
}

/***************************************************************************/

mz_stream_vtbl mz_stream_crc32_vtbl = {
    mz_stream_crc32_open,
    mz_stream_crc32_is_open,
    mz_stream_crc32_read,
    mz_stream_crc32_write,
    mz_stream_crc32_tell,
    mz_stream_crc32_seek,
    mz_stream_crc32_close,
    mz_stream_crc32_error,
    mz_stream_crc32_create,
    mz_stream_crc32_delete,
    mz_stream_crc32_get_prop_int64
};

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
    int32_t read = 0;
    read = mz_stream_read(crc32x->stream.base, buf, size);
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

int32_t mz_stream_crc32_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = crc32->total_in;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = crc32->total_out;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

void *mz_stream_crc32_create(void **stream)
{
    mz_stream_crc32 *crc32 = NULL;

    crc32 = (mz_stream_crc32 *)malloc(sizeof(mz_stream_crc32));
    if (crc32 != NULL)
    {
        memset(crc32, 0, sizeof(mz_stream_crc32));
        crc32->stream.vtbl = &mz_stream_crc32_vtbl;
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

void *mz_stream_crc32_get_interface(void)
{
    return (void *)&mz_stream_crc32_vtbl;
}

/***************************************************************************/

typedef struct mz_stream_raw_s {
    mz_stream   stream;
    int64_t     total_in;
    int64_t     total_out;
    int64_t     max_total_in;
} mz_stream_raw;

/***************************************************************************/

int32_t mz_stream_raw_open(void *stream, const char *path, int32_t mode)
{
    return MZ_OK;
}

int32_t mz_stream_raw_is_open(void *stream)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    return mz_stream_is_open(raw->stream.base);
}

int32_t mz_stream_raw_read(void *stream, void *buf, int32_t size)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    int32_t bytes_to_read = size;
    int32_t read = 0;

    if (raw->max_total_in > 0)
    {
        if ((raw->max_total_in - raw->total_in) < size)
            bytes_to_read = (int32_t)(raw->max_total_in - raw->total_in);
    }

    read = mz_stream_read(raw->stream.base, buf, bytes_to_read);

    if (read > 0)
        raw->total_in += read;

    return read;
}

int32_t mz_stream_raw_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    int32_t written = mz_stream_write(raw->stream.base, buf, size);
    if (written > 0)
        raw->total_out += written;
    return written;
}

int64_t mz_stream_raw_tell(void *stream)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    return mz_stream_tell(raw->stream.base);
}

int32_t mz_stream_raw_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    return mz_stream_seek(raw->stream.base, offset, origin);
}

int32_t mz_stream_raw_close(void *stream)
{
    return MZ_OK;
}

int32_t mz_stream_raw_error(void *stream)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    return mz_stream_error(raw->stream.base);
}

int32_t mz_stream_raw_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = raw->total_in;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = raw->total_out;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

int32_t mz_stream_raw_set_prop_int64(void *stream, int32_t prop, int64_t value)
{
    mz_stream_raw *raw = (mz_stream_raw *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        raw->max_total_in = value;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

/***************************************************************************/

mz_stream_vtbl mz_stream_raw_vtbl = {
    mz_stream_raw_open,
    mz_stream_raw_is_open,
    mz_stream_raw_read,
    mz_stream_raw_write,
    mz_stream_raw_tell,
    mz_stream_raw_seek,
    mz_stream_raw_close,
    mz_stream_raw_error,
    mz_stream_raw_create,
    mz_stream_raw_delete,
    mz_stream_raw_get_prop_int64,
    mz_stream_raw_set_prop_int64
};

/***************************************************************************/

void *mz_stream_raw_create(void **stream)
{
    mz_stream_raw *raw = NULL;

    raw = (mz_stream_raw *)malloc(sizeof(mz_stream_raw));
    if (raw != NULL)
    {
        memset(raw, 0, sizeof(mz_stream_raw));
        raw->stream.vtbl = &mz_stream_raw_vtbl;
    }
    if (stream != NULL)
        *stream = raw;

    return raw;
}

void mz_stream_raw_delete(void **stream)
{
    mz_stream_raw *raw = NULL;
    if (stream == NULL)
        return;
    raw = (mz_stream_raw *)*stream;
    if (raw != NULL)
        free(raw);
    *stream = NULL;
}
