/* mz_strm_crc32.c -- Stream for CRC32 hashing
   Version 2.7.1, November 1, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_crc32.h"
#ifdef HAVE_LZMA
#include "mz_strm_lzma.h"
#endif
#ifdef HAVE_ZLIB
#include "mz_strm_zlib.h"
#endif

/***************************************************************************/

static mz_stream_vtbl mz_stream_crc32_vtbl = {
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
    mz_stream_crc32_get_prop_int64,
    NULL
};

/***************************************************************************/

typedef struct mz_stream_crc32_s {
    mz_stream  stream;
    int8_t     initialized;
    int64_t    value;
    int64_t    total_in;
    int64_t    total_out;
    mz_stream_crc32_update
               update;
} mz_stream_crc32;

/***************************************************************************/

int32_t mz_stream_crc32_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;

    MZ_UNUSED(path);
    MZ_UNUSED(mode);

    crc32->initialized = 1;
    crc32->value = 0;
    return MZ_OK;
}

int32_t mz_stream_crc32_is_open(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    if (crc32->initialized != 1)
        return MZ_OPEN_ERROR;
    return MZ_OK;
}

int32_t mz_stream_crc32_read(void *stream, void *buf, int32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    int32_t read = 0;
    read = mz_stream_read(crc32x->stream.base, buf, size);
    if (read > 0)
    {
        crc32x->value = crc32x->update(crc32x->value, buf, read);
        crc32x->total_in += read;
    }
    return read;
}

int32_t mz_stream_crc32_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_crc32 *crc32x = (mz_stream_crc32 *)stream;
    int32_t written = 0;
    written = mz_stream_write(crc32x->stream.base, buf, size);
    if (written > 0)
    {
        crc32x->value = crc32x->update(crc32x->value, buf, written);
        crc32x->total_out += written;
    }
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
    crc32->value = 0;
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

uint32_t mz_stream_crc32_get_value(void *stream)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    return (uint32_t)crc32->value;
}

int32_t mz_stream_crc32_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_crc32 *crc32 = (mz_stream_crc32 *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = crc32->total_in;
        break;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = crc32->total_out;
        break;
    default:
        return MZ_EXIST_ERROR;
    }
    return MZ_OK;
}

void *mz_stream_crc32_create(void **stream)
{
    mz_stream_crc32 *crc32 = NULL;

    crc32 = (mz_stream_crc32 *)MZ_ALLOC(sizeof(mz_stream_crc32));
    if (crc32 != NULL)
    {
        memset(crc32, 0, sizeof(mz_stream_crc32));
        crc32->stream.vtbl = &mz_stream_crc32_vtbl;
#ifdef HAVE_ZLIB
        crc32->update =
            (mz_stream_crc32_update)mz_stream_zlib_get_crc32_update();
#elif defined(HAVE_LZMA)
        crc32->update =
            (mz_stream_crc32_update)mz_stream_lzma_get_crc32_update();
#else
#error ZLIB or LZMA required for CRC32
#endif
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
        MZ_FREE(crc32);
    *stream = NULL;
}

void *mz_stream_crc32_get_interface(void)
{
    return (void *)&mz_stream_crc32_vtbl;
}

int32_t mz_stream_crc32_get_update_func(mz_stream_crc32_update *update)
{
    if (update == NULL)
        return MZ_PARAM_ERROR;
#ifdef HAVE_ZLIB
    *update =
        (mz_stream_crc32_update)mz_stream_zlib_get_crc32_update();
#elif defined(HAVE_LZMA)
    *update =
        (mz_stream_crc32_update)mz_stream_lzma_get_crc32_update();
#else
#error ZLIB or LZMA required for CRC32
#endif
    return MZ_OK;
}
