/* mzstrm_bzip.c -- Stream for bzip inflate/deflate
   part of MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as bzip.
   See the accompanying LICENSE file for the full text of the license.
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "bzip2\bzlib.h"

#include "mz_strm.h"
#include "mz_strm_bzip.h"

/***************************************************************************/

typedef struct mz_stream_bzip_s {
    mz_stream   stream;
    bz_stream   bzstream;
    uint8_t     buffer[UINT16_MAX];
    int32_t     buffer_len;
    int64_t     total_in;
    int64_t     total_out;
    int64_t     max_total_in;
    int8_t      initialized;
    int16_t     level;
    int16_t     mode;
    int16_t     error;
} mz_stream_bzip;

/***************************************************************************/

int32_t mz_stream_bzip_open(void *stream, const char *path, int mode)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;


    bzip->bzstream.bzalloc = 0;
    bzip->bzstream.bzfree = 0;
    bzip->bzstream.opaque = 0;
    bzip->bzstream.total_in_lo32 = 0;
    bzip->bzstream.total_in_hi32 = 0;
    bzip->bzstream.total_out_lo32 = 0;
    bzip->bzstream.total_out_hi32 = 0;

    bzip->total_in = 0;
    bzip->total_out = 0;

    if (mode & MZ_STREAM_MODE_READ)
    {
        bzip->bzstream.next_in = bzip->buffer;
        bzip->bzstream.avail_in = 0;

        bzip->error = BZ2_bzDecompressInit(&bzip->bzstream, 0, 0);
    }
    else if (mode & MZ_STREAM_MODE_WRITE)
    {
        bzip->bzstream.next_out = bzip->buffer;
        bzip->bzstream.avail_out = sizeof(bzip->buffer);

        bzip->error = BZ2_bzCompressInit(&bzip->bzstream, bzip->level, 0, 35);
    }

    if (bzip->error != BZ_OK)
        return MZ_STREAM_ERROR;

    bzip->initialized = 1;
    bzip->mode = mode;
    return MZ_OK;
}

int32_t mz_stream_bzip_is_open(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    if (bzip->initialized != 1)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_bzip_read(void *stream, void *buf, uint32_t size)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;
    int32_t bytes_to_read = 0;
    int32_t read = 0;
    int16_t err = BZ_OK;

    bzip->bzstream.next_out = (uint8_t*)buf;
    bzip->bzstream.avail_out = (uint16_t)size;

    do
    {
        if (bzip->bzstream.avail_in == 0)
        {
            bytes_to_read = sizeof(bzip->buffer);
            if (bzip->max_total_in > 0)
            {
                if ((bzip->max_total_in - bzip->total_in) < sizeof(bzip->buffer))
                    bytes_to_read = (int32_t)(bzip->max_total_in - bzip->total_in);
            }    

            read = mz_stream_read(bzip->stream.base, bzip->buffer, bytes_to_read);
            if (mz_stream_error(bzip->stream.base))
            {
                bzip->error = BZ_IO_ERROR;
                break;
            }
            if (read == 0)
                break;

            bzip->total_in += read;

            bzip->bzstream.next_in = bzip->buffer;
            bzip->bzstream.avail_in = read;
        }

        total_out_before = bzip->bzstream.total_out_lo32 + 
                (((uint64_t)bzip->bzstream.total_out_hi32) << 32);

        err = BZ2_bzDecompress(&bzip->bzstream);

        total_out_after = bzip->bzstream.total_out_lo32 + 
                (((uint64_t)bzip->bzstream.total_out_hi32) << 32);

        out_bytes = (uint32_t)(total_out_after - total_out_before);
        total_out += out_bytes;

        if (err == BZ_STREAM_END)
            break;
        if (err != BZ_RUN_OK)
        {
            bzip->error = err;
            break;
        }
    }
    while (bzip->bzstream.avail_out > 0);

    bzip->total_out += total_out;

    return total_out;
}

int32_t mz_stream_bzip_flush(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    if (mz_stream_write(bzip->stream.base, bzip->buffer, bzip->buffer_len) != bzip->buffer_len)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

uint32_t mz_stream_bzip_compress(void *stream, int flush)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    int16_t err = BZ_OK;

    total_out_before = bzip->bzstream.total_out_lo32 + 
            (((uint64_t)bzip->bzstream.total_out_hi32) << 32);

    err = BZ2_bzCompress(&bzip->bzstream, flush);

    total_out_after = bzip->bzstream.total_out_lo32 + 
            (((uint64_t)bzip->bzstream.total_out_hi32) << 32);

    out_bytes = (uint32_t)(total_out_after - total_out_before);

    if (err != BZ_OK && err != BZ_STREAM_END)
    {
        bzip->error = err;
        return MZ_STREAM_ERROR;
    }

    return out_bytes;
}

int32_t mz_stream_bzip_write(void *stream, const void *buf, uint32_t size)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;


    bzip->bzstream.next_in = (uint8_t*)buf;
    bzip->bzstream.avail_in = size;

    while ((bzip->error == BZ_OK) && (bzip->bzstream.avail_in > 0))
    {
        if (bzip->bzstream.avail_out == 0)
        {
            if (mz_stream_bzip_flush(bzip) != MZ_OK)
            {
                bzip->error = BZ_DATA_ERROR;
                return 0;
            }

            bzip->bzstream.avail_out = sizeof(bzip->buffer);
            bzip->bzstream.next_out = bzip->buffer;

            bzip->buffer_len = 0;
        }
        
        out_bytes = mz_stream_bzip_compress(stream, BZ_RUN);

        total_out += out_bytes;
        bzip->buffer_len += out_bytes;
    }

    bzip->total_in += size;
    bzip->total_out += total_out;

    return size;
}

int64_t mz_stream_bzip_tell(void *stream)
{
    mz_stream_bzip *mem = (mz_stream_bzip *)stream;
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_bzip_seek(void *stream, uint64_t offset, int origin)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_bzip_close(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    uint32_t out_bytes = 0;

    if (bzip->mode & MZ_STREAM_MODE_READ)
    {
        BZ2_bzDecompressEnd(&bzip->bzstream);
    }
    else if (bzip->mode & MZ_STREAM_MODE_WRITE)
    {
        out_bytes = mz_stream_bzip_compress(stream, BZ_FINISH);

        bzip->buffer_len += out_bytes;
        bzip->total_out += out_bytes;

        mz_stream_bzip_flush(stream);

        bzip->error = BZ2_bzCompressEnd(&bzip->bzstream);
    }

    bzip->initialized = 0;

    if (bzip->error != BZ_OK)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_bzip_error(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    return bzip->error;
}

void mz_stream_bzip_set_level(void *stream, int16_t level)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    bzip->level = level;
}

int64_t mz_stream_bzip_get_total_in(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    return bzip->total_in;
}

int64_t mz_stream_bzip_get_total_out(void *stream)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    return bzip->total_out;
}

void mz_stream_bzip_set_max_total_in(void *stream, int64_t max_total_in)
{
    mz_stream_bzip *bzip = (mz_stream_bzip *)stream;
    bzip->max_total_in = max_total_in;
}

void *mz_stream_bzip_create(void **stream)
{
    mz_stream_bzip *bzip = NULL;

    bzip = (mz_stream_bzip *)malloc(sizeof(mz_stream_bzip));
    if (bzip != NULL)
    {
        memset(bzip, 0, sizeof(mz_stream_bzip));

        bzip->stream.open = mz_stream_bzip_open;
        bzip->stream.is_open = mz_stream_bzip_is_open;
        bzip->stream.read = mz_stream_bzip_read;
        bzip->stream.write = mz_stream_bzip_write;
        bzip->stream.tell = mz_stream_bzip_tell;
        bzip->stream.seek = mz_stream_bzip_seek;
        bzip->stream.close = mz_stream_bzip_close;
        bzip->stream.error = mz_stream_bzip_error;
        bzip->stream.create = mz_stream_bzip_create;
        bzip->stream.delete = mz_stream_bzip_delete;
        bzip->stream.get_total_in = mz_stream_bzip_get_total_in;
        bzip->stream.get_total_out = mz_stream_bzip_get_total_out;
        bzip->level = 6;
    }
    if (stream != NULL)
        *stream = bzip;

    return bzip;
}

void mz_stream_bzip_delete(void **stream)
{
    mz_stream_bzip *bzip = NULL;
    if (stream == NULL)
        return;
    bzip = (mz_stream_bzip *)*stream;
    if (bzip != NULL)
        free(bzip);
}

extern void bz_internal_error(int errcode)
{
}