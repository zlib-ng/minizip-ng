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

#include "aes/aes.h"
#include "aes/fileenc.h"
#include "aes/prng.h"

#include "ioapi_aes.h"

#define AES_METHOD          (99)
#define AES_PWVERIFYSIZE    (2)
#define AES_AUTHCODESIZE    (10)
#define AES_MAXSALTLENGTH   (16)
#define AES_VERSION         (0x0001)
#define AES_ENCRYPTIONMODE  (0x03)

typedef struct mzstream_aes_s {
    mzstream        stream;
    fcrypt_ctx      crypt_ctx;
    int16_t         mode;
    int16_t         initialized;
    int16_t         error;
    int16_t         encryption_mode;
    char            *password;
    uint64_t        total_in;
    uint64_t        total_out;
} mzstream_aes;

int32_t ZCALLBACK mzstream_aes_open(voidpf stream, const char *filename, int mode)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    uint16_t salt_length = 0;
    uint8_t verify[AES_PWVERIFYSIZE];
    uint8_t verify_expected[AES_PWVERIFYSIZE];
    uint8_t salt_value[AES_MAXSALTLENGTH];
    prng_ctx rng_ctx[1];

    aes->total_in = 0;
    aes->total_out = 0;
    aes->initialized = 0;

    if (mzstream_is_open(aes->stream.base) == MZSTREAM_ERR)
        return MZSTREAM_ERR;
    if (aes->password == NULL)
        return MZSTREAM_ERR;

    salt_length = SALT_LENGTH(aes->encryption_mode);

    if (mode & MZSTREAM_MODE_WRITE)
    {
        prng_init(mzstream_os_rand, rng_ctx);
        prng_rand(salt_value, salt_length, rng_ctx);
        prng_end(rng_ctx);

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)aes->password, 
            (uint32_t)strlen(aes->password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZSTREAM_ERR;

        if (mzstream_write(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZSTREAM_ERR;

        aes->total_out += salt_length;

        if (mzstream_write(aes->stream.base, verify, AES_PWVERIFYSIZE) != AES_PWVERIFYSIZE)
            return MZSTREAM_ERR;

        aes->total_out += AES_PWVERIFYSIZE;
    }
    else if (mode & MZSTREAM_MODE_READ)
    {
        if (mzstream_read(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZSTREAM_ERR;

        aes->total_in += salt_length;

        if (mzstream_read(aes->stream.base, verify_expected, AES_PWVERIFYSIZE) != AES_PWVERIFYSIZE)
            return MZSTREAM_ERR;

        aes->total_in += AES_PWVERIFYSIZE;

        if (fcrypt_init(aes->encryption_mode, (uint8_t *)aes->password,
            (uint32_t)strlen(aes->password), salt_value, verify, &aes->crypt_ctx) != 0)
            return MZSTREAM_ERR;

        if (memcmp(verify_expected, verify, AES_PWVERIFYSIZE) != 0)
            return MZSTREAM_ERR;
    }

    aes->mode = mode;
    aes->initialized = 1;

    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_aes_is_open(voidpf stream)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    if (aes->initialized == 0)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_aes_read(voidpf stream, void *buf, uint32_t size)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    uint32_t read = 0;
    read = mzstream_read(aes->stream.base, buf, size);
    if (read > 0)
        fcrypt_decrypt((uint8_t *)buf, read, &aes->crypt_ctx);
    aes->total_in += read;
    return read;
}

int32_t ZCALLBACK mzstream_aes_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    uint32_t written = 0;
    fcrypt_encrypt((uint8_t *)buf, size, &aes->crypt_ctx);
    written = mzstream_write(aes->stream.base, buf, size);
    if (written > 0)
        aes->total_out += written;
    return written;
}

int64_t ZCALLBACK mzstream_aes_tell(voidpf stream)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    return mzstream_tell(aes->stream.base);
}

int32_t ZCALLBACK mzstream_aes_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    return mzstream_seek(aes->stream.base, offset, origin);
}

int32_t ZCALLBACK mzstream_aes_close(voidpf stream)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    uint8_t authcode[AES_AUTHCODESIZE];
    uint8_t authcode_expected[AES_AUTHCODESIZE];

    if (aes->mode & MZSTREAM_MODE_WRITE)
    {
        fcrypt_end(authcode, &aes->crypt_ctx);

        if (mzstream_write(aes->stream.base, authcode, AES_AUTHCODESIZE) != AES_AUTHCODESIZE)
            return MZSTREAM_ERR;

        aes->total_out += AES_AUTHCODESIZE;
    }
    else if (aes->mode & MZSTREAM_MODE_READ)
    {
        if (mzstream_read(aes->stream.base, authcode, AES_AUTHCODESIZE) != AES_AUTHCODESIZE)
            return MZSTREAM_ERR;

        aes->total_in += AES_AUTHCODESIZE;

        if (fcrypt_end(authcode_expected, &aes->crypt_ctx) != AES_AUTHCODESIZE)
            return MZSTREAM_ERR;
        if (memcmp(authcode, authcode_expected, AES_AUTHCODESIZE) != 0)
            return MZSTREAM_ERR;
    }

    aes->initialized = 0;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_aes_error(voidpf stream)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    return aes->error;
}

void mzstream_aes_set_password(voidpf stream, char *password)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    aes->password = password;
}

void mzstream_aes_set_encryption_mode(voidpf stream, int16_t encryption_mode)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    aes->encryption_mode = encryption_mode;
}

voidpf mzstream_aes_alloc(void)
{
    mzstream_aes *aes = NULL;

    aes = (mzstream_aes *)malloc(sizeof(mzstream_aes));
    if (aes == NULL)
        return NULL;

    memset(aes, 0, sizeof(mzstream_aes));

    aes->stream.open = mzstream_aes_open;
    aes->stream.is_open = mzstream_aes_is_open;
    aes->stream.read = mzstream_aes_read;
    aes->stream.write = mzstream_aes_write;
    aes->stream.tell = mzstream_aes_tell;
    aes->stream.seek = mzstream_aes_seek;
    aes->stream.close = mzstream_aes_close;
    aes->stream.error = mzstream_aes_error;
    aes->stream.alloc = mzstream_aes_alloc;
    aes->stream.free = mzstream_aes_free;
    aes->encryption_mode = AES_ENCRYPTIONMODE;

    return (voidpf)aes;
}

void mzstream_aes_free(voidpf stream)
{
    mzstream_aes *aes = (mzstream_aes *)stream;
    if (aes != NULL)
    {
        free(aes);
    }
}