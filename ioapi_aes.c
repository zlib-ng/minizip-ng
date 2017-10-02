/* ioapi_aes.c -- IO base function header for compress/uncompress .zip
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

#include "ioapi_aes.h"

#include "crypt.h"

#define AES_METHOD          (99)
#define AES_PWVERIFYSIZE    (2)
#define AES_AUTHCODESIZE    (10)
#define AES_MAXSALTLENGTH   (16)
#define AES_VERSION         (0x0001)
#define AES_ENCRYPTIONMODE  (0x03)

#include "aes/aes.h"
#include "aes/fileenc.h"
#include "aes/prng.h"

typedef struct mz_stream_aes_s {
    mz_stream        stream;
    fcrypt_ctx      crypt_ctx;
    int16_t         mode;
    int16_t         initialized;
    int16_t         error;
    int16_t         encryption_mode;
    char            *password;
    uint64_t        total_in;
    uint64_t        total_out;
} mz_stream_aes;

int32_t ZCALLBACK mz_stream_aes_open(voidpf stream, const char *filename, int mode)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint16_t salt_length = 0;
    uint8_t verify[AES_PWVERIFYSIZE];
    uint8_t verify_expected[AES_PWVERIFYSIZE];
    uint8_t salt_value[AES_MAXSALTLENGTH];
    prng_ctx rng_ctx[1];

    aes->total_in = 0;
    aes->total_out = 0;
    aes->initialized = 0;

    if (mz_stream_is_open(aes->stream.base) == MZ_STREAM_ERR)
        return MZ_STREAM_ERR;
    if (aes->password == NULL)
        return MZ_STREAM_ERR;

    salt_length = SALT_LENGTH(aes->encryption_mode);

    if (mode & MZ_STREAM_MODE_WRITE)
    {
        prng_init(cryptrand, rng_ctx);
        prng_rand(salt_value, salt_length, rng_ctx);
        prng_end(rng_ctx);

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)aes->password, 
            (uint32_t)strlen(aes->password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZ_STREAM_ERR;

        if (mz_stream_write(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERR;

        aes->total_out += salt_length;

        if (mz_stream_write(aes->stream.base, verify, AES_PWVERIFYSIZE) != AES_PWVERIFYSIZE)
            return MZ_STREAM_ERR;

        aes->total_out += AES_PWVERIFYSIZE;
    }
    else if (mode & MZ_STREAM_MODE_READ)
    {
        if (mz_stream_read(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERR;

        aes->total_in += salt_length;

        if (mz_stream_read(aes->stream.base, verify_expected, AES_PWVERIFYSIZE) != AES_PWVERIFYSIZE)
            return MZ_STREAM_ERR;

        aes->total_in += AES_PWVERIFYSIZE;

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)aes->password,
            (uint32_t)strlen(aes->password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZ_STREAM_ERR;

        if (memcmp(verify_expected, verify, AES_PWVERIFYSIZE) != 0)
            return MZ_STREAM_ERR;
    }

    aes->mode = mode;
    aes->initialized = 1;

    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_aes_is_open(voidpf stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    if (aes->initialized == 0)
        return MZ_STREAM_ERR;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_aes_read(voidpf stream, void *buf, uint32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint32_t read = 0;
    read = mz_stream_read(aes->stream.base, buf, size);
    if (read > 0)
        fcrypt_decrypt((uint8_t *)buf, read, &aes->crypt_ctx);
    aes->total_in += read;
    return read;
}

int32_t ZCALLBACK mz_stream_aes_write(voidpf stream, const void *buf, uint32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint32_t written = 0;
    fcrypt_encrypt((uint8_t *)buf, size, &aes->crypt_ctx);
    written = mz_stream_write(aes->stream.base, buf, size);
    if (written > 0)
        aes->total_out += written;
    return written;
}

int64_t ZCALLBACK mz_stream_aes_tell(voidpf stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return mz_stream_tell(aes->stream.base);
}

int32_t ZCALLBACK mz_stream_aes_seek(voidpf stream, uint64_t offset, int origin)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return mz_stream_seek(aes->stream.base, offset, origin);
}

int32_t ZCALLBACK mz_stream_aes_close(voidpf stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    unsigned char authcode[AES_AUTHCODESIZE];
    unsigned char rauthcode[AES_AUTHCODESIZE];

    if (aes->mode & MZ_STREAM_MODE_WRITE)
    {
        fcrypt_end(authcode, &aes->crypt_ctx);

        if (mz_stream_write(aes->stream.base, authcode, AES_AUTHCODESIZE) != AES_AUTHCODESIZE)
            return MZ_STREAM_ERR;

        aes->total_out += AES_AUTHCODESIZE;
    }
    else if (aes->mode & MZ_STREAM_MODE_READ)
    {
        if (mz_stream_read(aes->stream.base, authcode, AES_AUTHCODESIZE) != AES_AUTHCODESIZE)
            return MZ_STREAM_ERR;

        aes->total_in += AES_AUTHCODESIZE;

        if (fcrypt_end(rauthcode, &aes->crypt_ctx) != AES_AUTHCODESIZE)
            return MZ_STREAM_ERR;
        if (memcmp(authcode, rauthcode, AES_AUTHCODESIZE) != 0)
            return MZ_STREAM_ERR;
    }

    aes->initialized = 0;
    return MZ_STREAM_OK;
}

int32_t ZCALLBACK mz_stream_aes_error(voidpf stream)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    return aes->error;
}

void mz_stream_aes_set_password(voidpf stream, char *password)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    aes->password = password;
}

void mz_stream_aes_set_encryption_mode(voidpf stream, int16_t encryption_mode)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    aes->encryption_mode = encryption_mode;
}

voidpf mz_stream_aes_create(voidpf *stream)
{
    mz_stream_aes *aes = NULL;

    aes = (mz_stream_aes *)malloc(sizeof(mz_stream_aes));
    if (aes != NULL)
    {
        memset(aes, 0, sizeof(mz_stream_aes));

        aes->stream.open = mz_stream_aes_open;
        aes->stream.is_open = mz_stream_aes_is_open;
        aes->stream.read = mz_stream_aes_read;
        aes->stream.write = mz_stream_aes_write;
        aes->stream.tell = mz_stream_aes_tell;
        aes->stream.seek = mz_stream_aes_seek;
        aes->stream.close = mz_stream_aes_close;
        aes->stream.error = mz_stream_aes_error;
        aes->stream.create = mz_stream_aes_create;
        aes->stream.delete = mz_stream_aes_delete;
        aes->encryption_mode = AES_ENCRYPTIONMODE;
    }
    if (stream != NULL)
        *stream = aes;

    return (voidpf)aes;
}

void mz_stream_aes_delete(voidpf *stream)
{
    mz_stream_aes *aes = NULL;
    if (stream == NULL)
        return;
    aes = (mz_stream_aes *)*stream;
    if (aes != NULL)
        free(aes);
}