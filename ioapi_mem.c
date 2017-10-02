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

#include "ioapi_mem.h"

typedef struct mz_stream_mem_s {
    mz_stream           stream;
    char                *buffer;    // Memory buffer pointer 
    uint32_t            size;       // Size of the memory buffer
    uint32_t            limit;      // Furthest we've written
    uint32_t            position;   // Current positoin in the memory
    int16_t             growable;   // Growable memory buffer
} mz_stream_mem;

int32_t ZCALLBACK mz_stream_mem_open(voidpf stream, const char *filename, int mode)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;

    if (mode & MZ_STREAM_MODE_CREATE)
    {
        if (mem->growable)
        {
            mem->size = UINT16_MAX;
            mem->buffer = (char *)malloc(mem->size);
        }

        // When writing we start with 0 bytes written
        mem->limit = 0;
    }
    else
    {
        mem->limit = mem->size;
    }

    mem->position = 0;

    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_mem_is_open(voidpf stream)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    if (mem->buffer == NULL)
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_mem_read(voidpf stream, void *buf, uint32_t size)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;

    if (size > mem->size - mem->position)
        size = mem->size - mem->position;

    memcpy(buf, mem->buffer + mem->position, size);
    mem->position += size;

    return size;
}

int32_t ZCALLBACK mz_stream_mem_write(voidpf stream, const void *buf, uint32_t size)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    uint32_t new_size = 0;
    char *new_buf = NULL;

    if (size > mem->size - mem->position)
    {
        if (mem->growable)
        {
            new_size = mem->size;
            if (size < UINT16_MAX)
                new_size += UINT16_MAX;
            else
                new_size += size;

            new_buf = (char *)malloc(new_size);

            memcpy(new_buf, mem->buffer, mem->size);
            free(mem->buffer);

            mem->buffer = new_buf;
            mem->size = new_size;
        }
        else
        {
            size = mem->size - mem->position;
        }
    }

    memcpy(mem->buffer + mem->position, buf, size);

    mem->position += size;
    if (mem->position > mem->limit)
        mem->limit = mem->position;

    return size;
}

int64_t ZCALLBACK mz_stream_mem_tell(voidpf stream)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    return mem->position;
}

int32_t ZCALLBACK mz_stream_mem_seek(voidpf stream, uint64_t offset, int origin)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    uint64_t new_pos = 0;

    switch (origin)
    {
        case MZ_STREAM_SEEK_CUR:
            new_pos = mem->position + offset;
            break;
        case MZ_STREAM_SEEK_END:
            new_pos = mem->limit + offset;
            break;
        case MZ_STREAM_SEEK_SET:
            new_pos = offset;
            break;
        default:
            return MZ_STREAM_ERR;
    }

    if (new_pos > mem->size)
        return MZ_STREAM_ERR;

    mem->position = (uint32_t)new_pos;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_mem_close(voidpf stream)
{
    // We never return errors
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_mem_error(voidpf stream)
{
    // We never return errors
    return MZ_STREAM_OK;
}

void mz_stream_mem_set_buffer(voidpf stream, void *buf, uint32_t size)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    mem->buffer = buf;
    mem->size = size;
}

void mz_stream_mem_set_growable(voidpf stream, int growable)
{
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    mem->growable = growable;
}

voidpf mz_stream_mem_create(voidpf *stream)
{
    mz_stream_mem *mem = NULL;

    mem = (mz_stream_mem *)malloc(sizeof(mz_stream_mem));
    if (mem != NULL)
    {
        memset(mem, 0, sizeof(mz_stream_mem));

        mem->stream.open = mz_stream_mem_open;
        mem->stream.is_open = mz_stream_mem_is_open;
        mem->stream.read = mz_stream_mem_read;
        mem->stream.write = mz_stream_mem_write;
        mem->stream.tell = mz_stream_mem_tell;
        mem->stream.seek = mz_stream_mem_seek;
        mem->stream.close = mz_stream_mem_close;
        mem->stream.error = mz_stream_mem_error;
        mem->stream.create = mz_stream_mem_create;
        mem->stream.delete = mz_stream_mem_delete;
    }
    if (stream == NULL)
        *stream = mem;

    return (voidpf)mem;
}

void mz_stream_mem_delete(voidpf *stream)
{
    mz_stream_mem *mem = NULL;
    if (stream == NULL)
        return;
    mem = (mz_stream_mem *)*stream;
    if (mem != NULL)
    {
        if (mem->growable && mem->buffer != NULL)
            free(mem->buffer);
        free(mem);
    }
}