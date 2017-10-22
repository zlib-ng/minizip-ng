/* mz_strm_aes.c -- Stream for WinZip AES encryption
   Version 2.2.0, October 22nd, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "fileenc.h"

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_aes.h"

/***************************************************************************/

#define MZ_AES_PWVERIFYSIZE    (2)
#define MZ_AES_AUTHCODESIZE    (10)
#define MZ_AES_MAXSALTLENGTH   (16)

/***************************************************************************/

mz_stream_vtbl mz_stream_aes_vtbl = {
    mz_stream_aes_open,
    mz_stream_aes_is_open,
    mz_stream_aes_read,
    mz_stream_aes_write,
    mz_stream_aes_tell,
    mz_stream_aes_seek,
    mz_stream_aes_close,
    mz_stream_aes_error,
    mz_stream_aes_create,
    mz_stream_aes_delete,
    mz_stream_aes_get_prop_int64
};

/***************************************************************************/

typedef struct mz_stream_aes_s {
    mz_stream      stream;
    int32_t        mode;
    int32_t        error;
    int16_t        initialized;
    uint8_t        buffer[INT16_MAX];
    int64_t        total_in;
    int64_t        total_out;
    fcrypt_ctx     crypt_ctx;
    int16_t        encryption_mode;
    const char     *password;
} mz_stream_aes;

/***************************************************************************/

int32_t mz_stream_aes_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint16_t salt_length = 0;
    uint8_t verify[MZ_AES_PWVERIFYSIZE];
    uint8_t verify_expected[MZ_AES_PWVERIFYSIZE];
    uint8_t salt_value[MZ_AES_MAXSALTLENGTH];
    const char *password = path;

    aes->total_in = 0;
    aes->total_out = 0;
    aes->initialized = 0;

    if (mz_stream_is_open(aes->stream.base) != MZ_OK)
        return MZ_STREAM_ERROR;
    if (password == NULL)
        password = aes->password;
    if (password == NULL)
        return MZ_STREAM_ERROR;

    salt_length = SALT_LENGTH(aes->encryption_mode);

    if (mode & MZ_STREAM_MODE_WRITE)
    {
        mz_os_rand(salt_value, salt_length);

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)password, 
            (uint32_t)strlen(password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZ_STREAM_ERROR;

        if (mz_stream_write(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERROR;

        aes->total_out += salt_length;

        if (mz_stream_write(aes->stream.base, verify, MZ_AES_PWVERIFYSIZE) != MZ_AES_PWVERIFYSIZE)
            return MZ_STREAM_ERROR;
        
        aes->total_out += MZ_AES_PWVERIFYSIZE;
    }
    else if (mode & MZ_STREAM_MODE_READ)
    {
        if (mz_stream_read(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERROR;

        aes->total_in += salt_length;

        if (mz_stream_read(aes->stream.base, verify_expected, MZ_AES_PWVERIFYSIZE) != MZ_AES_PWVERIFYSIZE)
            return MZ_STREAM_ERROR;

        aes->total_in += MZ_AES_PWVERIFYSIZE;

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)password,
            (uint32_t)strlen(password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZ_STREAM_ERROR;

        if (memcmp(verify_expected, verify, MZ_AES_PWVERIFYSIZE) != 0)
            return MZ_STREAM_ERROR;
    }

    aes->mode = mode;
    aes->initialized = 1;

    return MZ_OK;
}

int32_t mz_stream_aes_is_open(void *stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    if (aes->initialized == 0)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_aes_read(void *stream, void *buf, int32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    int32_t read = 0;
    read = mz_stream_read(aes->stream.base, buf, size);
    if (read > 0)
        fcrypt_decrypt((uint8_t *)buf, read, &aes->crypt_ctx);
    aes->total_in += read;
    return read;
}

int32_t mz_stream_aes_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    int32_t written = 0;
    if (size > sizeof(aes->buffer))
        return MZ_STREAM_ERROR;
    memcpy(aes->buffer, buf, size);
    fcrypt_encrypt((uint8_t *)aes->buffer, size, &aes->crypt_ctx);
    written = mz_stream_write(aes->stream.base, aes->buffer, size);
    if (written > 0)
        aes->total_out += written;
    return written;
}

int64_t mz_stream_aes_tell(void *stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return mz_stream_tell(aes->stream.base);
}

int32_t mz_stream_aes_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return mz_stream_seek(aes->stream.base, offset, origin);
}

int32_t mz_stream_aes_close(void *stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    unsigned char authcode[MZ_AES_AUTHCODESIZE];
    unsigned char rauthcode[MZ_AES_AUTHCODESIZE];

    if (aes->mode & MZ_STREAM_MODE_WRITE)
    {
        fcrypt_end(authcode, &aes->crypt_ctx);

        if (mz_stream_write(aes->stream.base, authcode, MZ_AES_AUTHCODESIZE) != MZ_AES_AUTHCODESIZE)
            return MZ_STREAM_ERROR;

        aes->total_out += MZ_AES_AUTHCODESIZE;
    }
    else if (aes->mode & MZ_STREAM_MODE_READ)
    {
        if (mz_stream_read(aes->stream.base, authcode, MZ_AES_AUTHCODESIZE) != MZ_AES_AUTHCODESIZE)
            return MZ_STREAM_ERROR;

        aes->total_in += MZ_AES_AUTHCODESIZE;

        if (fcrypt_end(rauthcode, &aes->crypt_ctx) != MZ_AES_AUTHCODESIZE)
            return MZ_STREAM_ERROR;
        if (memcmp(authcode, rauthcode, MZ_AES_AUTHCODESIZE) != 0)
            return MZ_CRC_ERROR;
    }

    aes->initialized = 0;
    return MZ_OK;
}

int32_t mz_stream_aes_error(void *stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return aes->error;
}

void mz_stream_aes_set_password(void *stream, const char *password)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    aes->password = password;
}

void mz_stream_aes_set_encryption_mode(void *stream, int16_t encryption_mode)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    aes->encryption_mode = encryption_mode;
}

int32_t mz_stream_aes_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN: 
        *value = aes->total_in;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_OUT: 
        *value = aes->total_out;
        return MZ_OK;
    case MZ_STREAM_PROP_HEADER_SIZE:
        *value = SALT_LENGTH(aes->encryption_mode) + MZ_AES_PWVERIFYSIZE;
        return MZ_OK;
    case MZ_STREAM_PROP_FOOTER_SIZE:
        *value = MZ_AES_AUTHCODESIZE;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

void *mz_stream_aes_create(void **stream)
{
    mz_stream_aes *aes = NULL;

    aes = (mz_stream_aes *)malloc(sizeof(mz_stream_aes));
    if (aes != NULL)
    {
        memset(aes, 0, sizeof(mz_stream_aes));
        aes->stream.vtbl = &mz_stream_aes_vtbl;
        aes->encryption_mode = MZ_AES_ENCRYPTION_MODE_256;
    }
    if (stream != NULL)
        *stream = aes;

    return aes;
}

void mz_stream_aes_delete(void **stream)
{
    mz_stream_aes *aes = NULL;
    if (stream == NULL)
        return;
    aes = (mz_stream_aes *)*stream;
    if (aes != NULL)
        free(aes);
    *stream = NULL;
}

void *mz_stream_aes_get_interface(void)
{
    return (void *)&mz_stream_aes_vtbl;
}
