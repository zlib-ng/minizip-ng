/* mz_strm_lzma.c -- Stream for lzma inflate/deflate
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as lzma.
   See the accompanying LICENSE file for the full text of the license.
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <lzma.h>

#include "mz_error.h"
#include "mz_strm.h"
#include "mz_strm_lzma.h"

/***************************************************************************/

#ifndef DEF_MEM_LEVEL
#  if MAX_MEM_LEVEL >= 8
#    define DEF_MEM_LEVEL 8
#  else
#    define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#  endif
#endif

/***************************************************************************/

mz_stream_vtbl mz_stream_lzma_vtbl = {
    mz_stream_lzma_open,
    mz_stream_lzma_is_open,
    mz_stream_lzma_read,
    mz_stream_lzma_write,
    mz_stream_lzma_tell,
    mz_stream_lzma_seek,
    mz_stream_lzma_close,
    mz_stream_lzma_error,
    mz_stream_lzma_create,
    mz_stream_lzma_delete,
    mz_stream_lzma_get_total_in,
    mz_stream_lzma_get_total_out
};

/***************************************************************************/

typedef struct mz_stream_lzma_s {
    mz_stream   stream;
    lzma_stream lstream;
    uint8_t     buffer[UINT16_MAX];
    int32_t     buffer_len;
    int64_t     total_in;
    int64_t     total_out;
    int64_t     max_total_in;
    int8_t      initialized;
    uint32_t    preset;
    int16_t     window_bits;
    int16_t     mem_level;
    int16_t     strategy;
    int16_t     mode;
    int16_t     error;
} mz_stream_lzma;

/***************************************************************************/

int32_t mz_stream_lzma_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    lzma_filter filters[LZMA_FILTERS_MAX + 1];
    lzma_options_lzma opt_lzma = { 0 };
    uint32_t size = 0;

    lzma->lstream.total_in = 0;
    lzma->lstream.total_out = 0;

    lzma->total_in = 0;
    lzma->total_out = 0;

    if (mode & MZ_STREAM_MODE_READ)
    {
        lzma->lstream.next_in = lzma->buffer;
        lzma->lstream.avail_in = 0;

        lzma->error = lzma_stream_decoder(&lzma->lstream, UINT64_MAX, LZMA_CONCATENATED);
    }
    else if (mode & MZ_STREAM_MODE_WRITE)
    {
        lzma->lstream.next_out = lzma->buffer;
        lzma->lstream.avail_out = sizeof(lzma->buffer);

        if (lzma_lzma_preset(&opt_lzma, lzma->preset))
            return MZ_STREAM_ERROR;

        memset(&filters, 0, sizeof(filters));

        filters[0].id = LZMA_FILTER_LZMA1;
        filters[0].options = &opt_lzma;
        filters[1].id = LZMA_VLI_UNKNOWN;

        lzma_properties_size(&size, (lzma_filter *)&filters);
        
        mz_stream_write_uint8(lzma->stream.base, LZMA_VERSION_MAJOR);
        mz_stream_write_uint8(lzma->stream.base, LZMA_VERSION_MINOR);
        mz_stream_write_uint16(lzma->stream.base, size);

        lzma->total_out += 4;

        lzma->error = lzma_alone_encoder(&lzma->lstream, &opt_lzma);
    }

    if (lzma->error != LZMA_OK)
        return MZ_STREAM_ERROR;

    lzma->initialized = 1;
    lzma->mode = mode;
    return MZ_OK;
}

int32_t mz_stream_lzma_is_open(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    if (lzma->initialized != 1)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

uint32_t mz_stream_lzma_code(void *stream, int32_t flush)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    int16_t err = LZMA_OK;

    total_out_before = lzma->lstream.total_out;
    err = lzma_code(&lzma->lstream, flush);
    total_out_after = lzma->lstream.total_out;

    out_bytes = (uint32_t)(total_out_after - total_out_before);

    if (err != LZMA_OK && err != LZMA_STREAM_END)
    {
        lzma->error = err;
        return MZ_STREAM_ERROR;
    }

    return out_bytes;
}

int32_t mz_stream_lzma_read(void *stream, void *buf, int32_t size)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    uint64_t total_out_before = 0;
    uint64_t total_out_after = 0;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;
    int32_t bytes_to_read = 0;
    int32_t read = 0;
    int16_t err = LZMA_OK;


    lzma->lstream.next_out = (uint8_t*)buf;
    lzma->lstream.avail_out = (uint16_t)size;

    do
    {
        if (lzma->lstream.avail_in == 0)
        {
            bytes_to_read = sizeof(lzma->buffer);
            if (lzma->max_total_in > 0)
            {
                if ((lzma->max_total_in - lzma->total_in) < sizeof(lzma->buffer))
                    bytes_to_read = (int32_t)(lzma->max_total_in - lzma->total_in);
            }
            
            read = mz_stream_read(lzma->stream.base, lzma->buffer, bytes_to_read);

            if (read < 0)
            {
                lzma->error = MZ_STREAM_ERROR;
                break;
            }
            if (read == 0)
                break;

            lzma->total_in += read;

            lzma->lstream.next_in = lzma->buffer;
            lzma->lstream.avail_in = read;
        }

        total_out_before = lzma->lstream.total_out;
        err = lzma_code(&lzma->lstream, LZMA_RUN);
        total_out_after = lzma->lstream.total_out;

        out_bytes = (int32_t)(total_out_after - total_out_before);
        total_out += out_bytes;

        if (err == LZMA_STREAM_END)
            break;
        if (err != LZMA_OK)
        {
            lzma->error = err;
            break;
        }
    }
    while (lzma->lstream.avail_out > 0);

    lzma->total_out += total_out;

    return total_out;
}

int32_t mz_stream_lzma_flush(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    if (mz_stream_write(lzma->stream.base, lzma->buffer, lzma->buffer_len) != lzma->buffer_len)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_lzma_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    uint32_t out_bytes = 0;
    uint32_t total_out = 0;


    lzma->lstream.next_in = (uint8_t*)buf;
    lzma->lstream.avail_in = size;

    while ((lzma->error == LZMA_OK) && (lzma->lstream.avail_in > 0))
    {
        if (lzma->lstream.avail_out == 0)
        {
            if (mz_stream_lzma_flush(lzma) != MZ_OK)
            {
                lzma->error = MZ_STREAM_ERROR;
                return 0;
            }

            lzma->lstream.avail_out = sizeof(lzma->buffer);
            lzma->lstream.next_out = lzma->buffer;

            lzma->buffer_len = 0;
        }
        
        out_bytes = mz_stream_lzma_code(stream, LZMA_RUN);

        total_out += out_bytes;
        lzma->buffer_len += out_bytes;
    }

    lzma->total_in += size;
    lzma->total_out += total_out;

    return size;
}

int64_t mz_stream_lzma_tell(void *stream)
{
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_lzma_seek(void *stream, int64_t offset, int32_t origin)
{
    return MZ_STREAM_ERROR;
}

int32_t mz_stream_lzma_close(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    uint32_t out_bytes = 0;

    if (lzma->mode & MZ_STREAM_MODE_READ)
    {
        lzma_end(&lzma->lstream);
    }
    else if (lzma->mode & MZ_STREAM_MODE_WRITE)
    {
        out_bytes = mz_stream_lzma_code(stream, LZMA_FINISH);
        
        lzma->buffer_len += out_bytes;
        lzma->total_out += out_bytes;

        mz_stream_lzma_flush(stream);

        lzma_end(&lzma->lstream);
    }

    lzma->initialized = 0;

    if (lzma->error != LZMA_OK)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_lzma_error(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    return lzma->error;
}

void mz_stream_lzma_set_level(void *stream, int16_t level)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;

    if (level == 9)
        lzma->preset = LZMA_PRESET_EXTREME;
    else
        lzma->preset = LZMA_PRESET_DEFAULT;
}

int64_t mz_stream_lzma_get_total_in(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    return lzma->total_in;
}

int64_t mz_stream_lzma_get_total_out(void *stream)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    return lzma->total_out;
}

void mz_stream_lzma_set_max_total_in(void *stream, int64_t max_total_in)
{
    mz_stream_lzma *lzma = (mz_stream_lzma *)stream;
    lzma->max_total_in = max_total_in;
}

void *mz_stream_lzma_create(void **stream)
{
    mz_stream_lzma *lzma = NULL;

    lzma = (mz_stream_lzma *)malloc(sizeof(mz_stream_lzma));
    if (lzma != NULL)
    {
        memset(lzma, 0, sizeof(mz_stream_lzma));
        lzma->stream.vtbl = &mz_stream_lzma_vtbl;
        lzma->preset = LZMA_PRESET_DEFAULT;
    }
    if (stream != NULL)
        *stream = lzma;

    return lzma;
}

void mz_stream_lzma_delete(void **stream)
{
    mz_stream_lzma *lzma = NULL;
    if (stream == NULL)
        return;
    lzma = (mz_stream_lzma *)*stream;
    if (lzma != NULL)
        free(lzma);
    *stream = NULL;
}

void *mz_stream_lzma_get_interface(void)
{
    return (void *)&mz_stream_lzma_vtbl;
}
