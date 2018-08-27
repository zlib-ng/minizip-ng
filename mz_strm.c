/* mz_strm.c -- Stream interface
   Version 2.5.1, August 18, 2018
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

/***************************************************************************/

static uint32_t mz_encoding_codepage437_to_utf8[256] = {
    0x000000, 0xba98e2, 0xbb98e2, 0xa599e2, 0xa699e2, 0xa399e2, 0xa099e2, 0xa280e2,
    0x9897e2, 0x8b97e2, 0x9997e2, 0x8299e2, 0x8099e2, 0xaa99e2, 0xab99e2, 0xbc98e2,
    0xba96e2, 0x8497e2, 0x9586e2, 0xbc80e2, 0x00b6c2, 0x00a7c2, 0xac96e2, 0xa886e2,
    0x9186e2, 0x9386e2, 0x9286e2, 0x9086e2, 0x9f88e2, 0x9486e2, 0xb296e2, 0xbc96e2,
    0x000020, 0x000021, 0x000022, 0x000023, 0x000024, 0x000025, 0x000026, 0x000027,
    0x000028, 0x000029, 0x00002a, 0x00002b, 0x00002c, 0x00002d, 0x00002e, 0x00002f,
    0x000030, 0x000031, 0x000032, 0x000033, 0x000034, 0x000035, 0x000036, 0x000037,
    0x000038, 0x000039, 0x00003a, 0x00003b, 0x00003c, 0x00003d, 0x00003e, 0x00003f,
    0x000040, 0x000041, 0x000042, 0x000043, 0x000044, 0x000045, 0x000046, 0x000047,
    0x000048, 0x000049, 0x00004a, 0x00004b, 0x00004c, 0x00004d, 0x00004e, 0x00004f,
    0x000050, 0x000051, 0x000052, 0x000053, 0x000054, 0x000055, 0x000056, 0x000057,
    0x000058, 0x000059, 0x00005a, 0x00005b, 0x00005c, 0x00005d, 0x00005e, 0x00005f,
    0x000060, 0x000061, 0x000062, 0x000063, 0x000064, 0x000065, 0x000066, 0x000067,
    0x000068, 0x000069, 0x00006a, 0x00006b, 0x00006c, 0x00006d, 0x00006e, 0x00006f,
    0x000070, 0x000071, 0x000072, 0x000073, 0x000074, 0x000075, 0x000076, 0x000077,
    0x000078, 0x000079, 0x00007a, 0x00007b, 0x00007c, 0x00007d, 0x00007e, 0x828ce2,
    0x0087c3, 0x00bcc3, 0x00a9c3, 0x00a2c3, 0x00a4c3, 0x00a0c3, 0x00a5c3, 0x00a7c3,
    0x00aac3, 0x00abc3, 0x00a8c3, 0x00afc3, 0x00aec3, 0x00acc3, 0x0084c3, 0x0085c3,
    0x0089c3, 0x00a6c3, 0x0086c3, 0x00b4c3, 0x00b6c3, 0x00b2c3, 0x00bbc3, 0x00b9c3,
    0x00bfc3, 0x0096c3, 0x009cc3, 0x00a2c2, 0x00a3c2, 0x00a5c2, 0xa782e2, 0x0092c6,
    0x00a1c3, 0x00adc3, 0x00b3c3, 0x00bac3, 0x00b1c3, 0x0091c3, 0x00aac2, 0x00bac2,
    0x00bfc2, 0x908ce2, 0x00acc2, 0x00bdc2, 0x00bcc2, 0x00a1c2, 0x00abc2, 0x00bbc2,
    0x9196e2, 0x9296e2, 0x9396e2, 0x8294e2, 0xa494e2, 0xa195e2, 0xa295e2, 0x9695e2,
    0x9595e2, 0xa395e2, 0x9195e2, 0x9795e2, 0x9d95e2, 0x9c95e2, 0x9b95e2, 0x9094e2,
    0x9494e2, 0xb494e2, 0xac94e2, 0x9c94e2, 0x8094e2, 0xbc94e2, 0x9e95e2, 0x9f95e2,
    0x9a95e2, 0x9495e2, 0xa995e2, 0xa695e2, 0xa095e2, 0x9095e2, 0xac95e2, 0xa795e2,
    0xa895e2, 0xa495e2, 0xa595e2, 0x9995e2, 0x9895e2, 0x9295e2, 0x9395e2, 0xab95e2,
    0xaa95e2, 0x9894e2, 0x8c94e2, 0x8896e2, 0x8496e2, 0x8c96e2, 0x9096e2, 0x8096e2,
    0x00b1ce, 0x009fc3, 0x0093ce, 0x0080cf, 0x00a3ce, 0x0083cf, 0x00b5c2, 0x0084cf,
    0x00a6ce, 0x0098ce, 0x00a9ce, 0x00b4ce, 0x9e88e2, 0x0086cf, 0x00b5ce, 0xa988e2,
    0xa189e2, 0x00b1c2, 0xa589e2, 0xa489e2, 0xa08ce2, 0xa18ce2, 0x00b7c3, 0x8889e2,
    0x00b0c2, 0x9988e2, 0x00b7c2, 0x9a88e2, 0xbf81e2, 0x00b2c2, 0xa096e2, 0x00a0c2
};

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

static int32_t mz_stream_read_value(void *stream, uint64_t *value, int32_t len)
{
    uint8_t buf[8];
    int32_t n = 0;
    int32_t i = 0;

    *value = 0;
    if (mz_stream_read(stream, buf, len) == len)
    {
        for (n = 0; n < len; n += 1, i += 8)
            *value += ((uint64_t)buf[n]) << i;
    }
    else if (mz_stream_error(stream))
        return MZ_STREAM_ERROR;
    else
        return MZ_END_OF_STREAM;

    return MZ_OK;
}

int32_t mz_stream_read_uint8(void *stream, uint8_t *value)
{
    int32_t err = MZ_OK;
    uint64_t value64 = 0;

    *value = 0;
    err = mz_stream_read_value(stream, &value64, sizeof(uint8_t));
    if (err == MZ_OK)
        *value = (uint8_t)value64;
    return err;
}

int32_t mz_stream_read_uint16(void *stream, uint16_t *value)
{
    int32_t err = MZ_OK;
    uint64_t value64 = 0;

    *value = 0;
    err = mz_stream_read_value(stream, &value64, sizeof(uint16_t));
    if (err == MZ_OK)
        *value = (uint16_t)value64;
    return err;
}

int32_t mz_stream_read_uint32(void *stream, uint32_t *value)
{
    int32_t err = MZ_OK;
    uint64_t value64 = 0;

    *value = 0;
    err = mz_stream_read_value(stream, &value64, sizeof(uint32_t));
    if (err == MZ_OK)
        *value = (uint32_t)value64;
    return err;
}

int32_t mz_stream_read_uint64(void *stream, uint64_t *value)
{
    return mz_stream_read_value(stream, value, sizeof(uint64_t));
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

int32_t mz_stream_write_chars(void *stream, const char *value, uint8_t null_terminate)
{
    int32_t len = (int32_t)strlen(value);
    if (null_terminate)
        len += 1;
    return mz_stream_write(stream, value, len);
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
        if (bytes_to_copy > (int32_t)sizeof(buf))
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

int32_t mz_stream_copy_cp437(void *target, void *source, int32_t len)
{
    uint32_t utf8_char = 0;
    uint8_t utf8_byte = 0;
    uint8_t cp437_char = 0;
    int32_t i = 0;
    int32_t x = 0;
    int32_t err = MZ_OK;
    int32_t written = 0;

    // Convert ibm codepage 437 encoding to utf-8 while copying
    for (i = 0; i < len; i += 1)
    {
        err = mz_stream_read_uint8(source, &cp437_char);
        if (err != MZ_OK)
            return err;

        utf8_char = mz_encoding_codepage437_to_utf8[cp437_char];
        for (x = 0; x < 32; x += 8)
        {
            utf8_byte = utf8_char >> x;
            if (x > 0 && utf8_byte == 0)
                continue;
            err = mz_stream_write_uint8(target, utf8_byte);
            if (err != MZ_OK)
                return err;
            written += 1;
        }
    }

    return written;
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

void* mz_stream_get_interface(void *stream)
{
    mz_stream *strm = (mz_stream *)stream;
    if (strm == NULL || strm->vtbl == NULL)
        return NULL;
    return (void *)strm->vtbl;
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
    if (strm != NULL && strm->vtbl != NULL && strm->vtbl->destroy != NULL)
        strm->vtbl->destroy(stream);
    *stream = NULL;
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
    MZ_UNUSED(stream);
    MZ_UNUSED(path);
    MZ_UNUSED(mode);

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
    MZ_UNUSED(stream);

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

static mz_stream_vtbl mz_stream_raw_vtbl = {
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

    raw = (mz_stream_raw *)MZ_ALLOC(sizeof(mz_stream_raw));
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
        MZ_FREE(raw);
    *stream = NULL;
}
