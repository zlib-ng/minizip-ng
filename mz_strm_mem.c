/* mz_strm_mem.c -- Stream for memory access
   part of the minizip-ng project

   This interface is designed to access memory rather than files.
   We do use a region of memory to put data in to and take it out of.

   Based on Unzip ioapi.c version 0.22, May 19th, 2003

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng
   Copyright (C) 2003 Justin Fletcher
   Copyright (C) 1998-2003 Gilles Vollant
     https://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"

/***************************************************************************/

static mz_stream_vtbl mz_stream_mem_vtbl = {mz_stream_mem_open,
                                            mz_stream_mem_is_open,
                                            mz_stream_mem_read,
                                            mz_stream_mem_write,
                                            mz_stream_mem_tell,
                                            mz_stream_mem_seek,
                                            mz_stream_mem_close,
                                            mz_stream_mem_error,
                                            mz_stream_mem_create,
                                            mz_stream_mem_delete,
                                            NULL,
                                            NULL};

/***************************************************************************/

typedef struct mz_stream_mem_s {
    mz_stream stream;
    int32_t mode;
    uint8_t *buffer;   /* Memory buffer pointer */
    int64_t size;      /* Size of the memory buffer */
    int64_t limit;     /* Furthest we've written */
    int64_t position;  /* Current position in the memory */
    int64_t grow_size; /* Size to grow when full */
} mz_stream_mem;

/***************************************************************************/

static int32_t mz_stream_mem_set_size(void *stream, int64_t size) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    uint8_t *new_buf = NULL;
    int64_t copy_size; 

    if (size <= 0)
        return MZ_BUF_ERROR;

    if (size > SIZE_MAX)
        return MZ_BUF_ERROR;

    new_buf = (uint8_t *)malloc((size_t) size);
    if (!new_buf)
        return MZ_BUF_ERROR;

    if (mem->buffer) {
        if (size < mem->limit)
            copy_size = size;
        else
            copy_size = mem->limit;

        memcpy(new_buf, mem->buffer, copy_size);
        free(mem->buffer);
    }

    mem->buffer = new_buf;
    mem->size = size;

    if (mem->limit > size)
        mem->limit = size;

    return MZ_OK;
}

int32_t mz_stream_mem_open(void *stream, const char *path, int32_t mode) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    int32_t err = MZ_OK;

    MZ_UNUSED(path);

    mem->mode = mode;
    mem->limit = 0;
    mem->position = 0;

    if (mem->mode & MZ_OPEN_MODE_CREATE)
        err = mz_stream_mem_set_size(stream, mem->grow_size);
    else
        mem->limit = mem->size;

    return err;
}

int32_t mz_stream_mem_is_open(void *stream) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    if (!mem->buffer)
        return MZ_OPEN_ERROR;
    return MZ_OK;
}

int64_t mz_stream_mem_read(void *stream, void *buf, int64_t size) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;

    if (size > mem->size - mem->position)
        size = mem->size - mem->position;
    if (mem->position + size > mem->limit)
        size = mem->limit - mem->position;

    if (size <= 0)
        return 0;

    memcpy(buf, mem->buffer + mem->position, size);
    mem->position += size;

    return size;
}

int64_t mz_stream_mem_write(void *stream, const void *buf, int64_t size) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    int64_t new_size = 0;
    int64_t required_size;
    int64_t grow_size;
    int32_t err = MZ_OK;

    if (size == 0)
        return 0;

    if (size <= 0)
        return MZ_PARAM_ERROR;

    if (size > INT64_MAX - mem->position) 
        return MZ_BUF_ERROR;

    if (mem->position + size > mem->size)
    {
        if (mem->mode & MZ_OPEN_MODE_CREATE) {
            new_size = mem->size;
            required_size = mem->position + size;
            grow_size = mem->grow_size;

            if (grow_size <= 0 || grow_size < required_size - new_size)
                grow_size = required_size - new_size;
            if (new_size > INT64_MAX - grow_size)
                return MZ_BUF_ERROR;

            new_size += grow_size;

            err = mz_stream_mem_set_size(stream, new_size);
            if (err != MZ_OK)
                return err;
        } else {
            size = mem->size - mem->position;
            if (size <=0)
                return 0;
        }
    }

    if (size <= 0)
        return 0;

    memcpy(mem->buffer + mem->position, buf, (size_t)size);

    mem->position += size;
    if (mem->position > mem->limit)
        mem->limit = mem->position;

    return size;
}

int64_t mz_stream_mem_tell(void *stream) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    return mem->position;
}

int64_t mz_stream_mem_seek(void *stream, int64_t offset, int32_t origin) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    int64_t new_pos = 0;
    int32_t err = MZ_OK;

    switch (origin) {
    case MZ_SEEK_CUR:
        if (offset > 0 && mem->position > INT64_MAX - offset)
            return MZ_SEEK_ERROR;
        if (offset < 0 && mem->position < INT64_MIN - offset)
            return MZ_SEEK_ERROR;
        new_pos = mem->position + offset;
        break;
    case MZ_SEEK_END:
        if (offset > 0 && mem->limit > INT64_MAX - offset)
            return MZ_SEEK_ERROR;
        if (offset < 0 && mem->limit < INT64_MIN - offset)
            return MZ_SEEK_ERROR;
        new_pos = mem->limit + offset;
        break;
    case MZ_SEEK_SET:
        new_pos = offset;
        break;
    default:
        return MZ_SEEK_ERROR;
    }

    if (new_pos < 0) {
        return MZ_SEEK_ERROR;
    }

    if (new_pos > mem->size) {
        if ((mem->mode & MZ_OPEN_MODE_CREATE) == 0)
            return MZ_SEEK_ERROR;

        err = mz_stream_mem_set_size(stream, new_pos);
        if (err != MZ_OK)
            return err;
    }

    mem->position = new_pos;
    return MZ_OK;
}

int32_t mz_stream_mem_close(void *stream) {
    MZ_UNUSED(stream);

    /* We never return errors */
    return MZ_OK;
}

int32_t mz_stream_mem_error(void *stream) {
    MZ_UNUSED(stream);

    /* We never return errors */
    return MZ_OK;
}

void mz_stream_mem_set_buffer(void *stream, void *buf, int64_t size) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    if (size < 0)
        size = 0;
    mem->buffer = (uint8_t *)buf;
    mem->size = size;
    mem->limit = size;
}

int32_t mz_stream_mem_get_buffer(void *stream, const void **buf) {
    return mz_stream_mem_get_buffer_at(stream, 0, buf);
}

int32_t mz_stream_mem_get_buffer_at(void *stream, int64_t position, const void **buf) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    if (!buf || position < 0 || !mem->buffer || mem->size < position)
        return MZ_SEEK_ERROR;
    *buf = mem->buffer + position;
    return MZ_OK;
}

int32_t mz_stream_mem_get_buffer_at_current(void *stream, const void **buf) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    return mz_stream_mem_get_buffer_at(stream, mem->position, buf);
}

void mz_stream_mem_get_buffer_length(void *stream, int64_t *length) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    *length = mem->limit;
}

void mz_stream_mem_set_buffer_limit(void *stream, int64_t limit) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;

    if (limit < 0)
        limit = 0;
    if (limit > mem->size)
        limit = mem->size;

    mem->limit = limit;
}

void mz_stream_mem_set_grow_size(void *stream, int32_t grow_size) {
    mz_stream_mem *mem = (mz_stream_mem *)stream;
    mem->grow_size = grow_size;
}

void *mz_stream_mem_create(void) {
    mz_stream_mem *mem = (mz_stream_mem *)calloc(1, sizeof(mz_stream_mem));
    if (mem) {
        mem->stream.vtbl = &mz_stream_mem_vtbl;
        mem->grow_size = 4096;
    }
    return mem;
}

void mz_stream_mem_delete(void **stream) {
    mz_stream_mem *mem = NULL;
    if (!stream)
        return;
    mem = (mz_stream_mem *)*stream;
    if (mem) {
        if ((mem->mode & MZ_OPEN_MODE_CREATE) && (mem->buffer))
            free(mem->buffer);
        free(mem);
    }
    *stream = NULL;
}

void *mz_stream_mem_get_interface(void) {
    return (void *)&mz_stream_mem_vtbl;
}
