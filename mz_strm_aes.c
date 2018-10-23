/* mz_strm_aes.c -- Stream for WinZip AES encryption
   Version 2.6.0, October 8, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
      https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2010 Brian Gladman, Worcester, UK

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/


#include <stdlib.h>
#include <string.h>

#include "aes.h"
#include "hmac.h"
#include "pwd2key.h"

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_aes.h"

/***************************************************************************/

#define MZ_AES_KEY_LENGTH(mode)     (8 * (mode & 3) + 8)
#define MZ_AES_KEY_LENGTH_MAX       (32)
#define MZ_AES_KEYING_ITERATIONS    (1000)
#define MZ_AES_SALT_LENGTH(mode)    (4 * (mode & 3) + 4)
#define MZ_AES_SALT_LENGTH_MAX      (16)
#define MZ_AES_MAC_LENGTH(mode)     (10)
#define MZ_AES_PW_LENGTH_MAX        (128)
#define MZ_AES_PW_VERIFY_SIZE       (2)
#define MZ_AES_AUTHCODE_SIZE        (10)

/***************************************************************************/

static mz_stream_vtbl mz_stream_aes_vtbl = {
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
    mz_stream_aes_get_prop_int64,
    mz_stream_aes_set_prop_int64
};

/***************************************************************************/

typedef struct mz_stream_aes_s {
    mz_stream       stream;
    int32_t         mode;
    int32_t         error;
    int16_t         initialized;
    uint8_t         buffer[INT16_MAX];
    int64_t         total_in;
    int64_t         max_total_in;
    int64_t         total_out;
    int16_t         encryption_mode;
    const char      *password;
    aes_encrypt_ctx encr_ctx[1];
    hmac_ctx        auth_ctx[1];
    uint8_t         nonce[AES_BLOCK_SIZE];
    uint8_t         encr_bfr[AES_BLOCK_SIZE];
    uint32_t        encr_pos;
} mz_stream_aes;

/***************************************************************************/

int32_t mz_stream_aes_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint16_t salt_length = 0;
    uint16_t password_length = 0;
    uint16_t key_length = 0;
    uint8_t kbuf[2 * MZ_AES_KEY_LENGTH_MAX + MZ_AES_PW_VERIFY_SIZE];
    uint8_t verify[MZ_AES_PW_VERIFY_SIZE];
    uint8_t verify_expected[MZ_AES_PW_VERIFY_SIZE];
    uint8_t salt_value[MZ_AES_SALT_LENGTH_MAX];
    const char *password = path;

    aes->total_in = 0;
    aes->total_out = 0;
    aes->initialized = 0;

    if (mz_stream_is_open(aes->stream.base) != MZ_OK)
        return MZ_STREAM_ERROR;

    if (password == NULL)
        password = aes->password;
    if (password == NULL)
        return MZ_PARAM_ERROR;
    password_length = (uint16_t)strlen(password);
    if (password_length > MZ_AES_PW_LENGTH_MAX)
        return MZ_PARAM_ERROR;

    if (aes->encryption_mode < 1 || aes->encryption_mode > 3)
        return MZ_PARAM_ERROR;
    salt_length = MZ_AES_SALT_LENGTH(aes->encryption_mode);

    if (mode & MZ_OPEN_MODE_WRITE)
    {
#ifdef MZ_ZIP_NO_COMPRESSION
        return MZ_SUPPORT_ERROR;
#else
        mz_os_rand(salt_value, salt_length);
#endif
    }
    else if (mode & MZ_OPEN_MODE_READ)
    {
#ifdef MZ_ZIP_NO_DECOMPRESSION
        return MZ_SUPPORT_ERROR;
#else
        if (mz_stream_read(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERROR;
#endif
    }

    key_length = MZ_AES_KEY_LENGTH(aes->encryption_mode);
    // Derive the encryption and authentication keys and the password verifier
    derive_key((const uint8_t *)password, password_length, salt_value, salt_length,
        MZ_AES_KEYING_ITERATIONS, kbuf, 2 * key_length + MZ_AES_PW_VERIFY_SIZE);

    // Initialize the encryption nonce and buffer pos
    aes->encr_pos = AES_BLOCK_SIZE;
    memset(aes->nonce, 0, AES_BLOCK_SIZE * sizeof(uint8_t));

    // Initialize for encryption using key 1
    aes_encrypt_key(kbuf, key_length, aes->encr_ctx);

    // Initialize for authentication using key 2
    hmac_sha_begin(HMAC_SHA1, aes->auth_ctx);
    hmac_sha_key(kbuf + key_length, key_length, aes->auth_ctx);

    memcpy(verify, kbuf + 2 * key_length, MZ_AES_PW_VERIFY_SIZE);

    if (mode & MZ_OPEN_MODE_WRITE)
    {
        if (mz_stream_write(aes->stream.base, salt_value, salt_length) != salt_length)
            return MZ_STREAM_ERROR;

        aes->total_out += salt_length;

        if (mz_stream_write(aes->stream.base, verify, MZ_AES_PW_VERIFY_SIZE) != MZ_AES_PW_VERIFY_SIZE)
            return MZ_STREAM_ERROR;

        aes->total_out += MZ_AES_PW_VERIFY_SIZE;
    }
    else if (mode & MZ_OPEN_MODE_READ)
    {
        aes->total_in += salt_length;

        if (mz_stream_read(aes->stream.base, verify_expected, MZ_AES_PW_VERIFY_SIZE) != MZ_AES_PW_VERIFY_SIZE)
            return MZ_STREAM_ERROR;

        aes->total_in += MZ_AES_PW_VERIFY_SIZE;

        if (memcmp(verify_expected, verify, MZ_AES_PW_VERIFY_SIZE) != 0)
            return MZ_PASSWORD_ERROR;
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

static int32_t mz_stream_aes_encrypt_data(void *stream, uint8_t *buf, int32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    uint32_t pos = aes->encr_pos;
    uint32_t i = 0;

    while (i < (uint32_t)size)
    {
        if (pos == AES_BLOCK_SIZE)
        {
            uint32_t j = 0;

            // Increment encryption nonce
            while (j < 8 && !++aes->nonce[j])
                j += 1;

            // Encrypt the nonce to form next xor buffer
            aes_encrypt(aes->nonce, aes->encr_bfr, aes->encr_ctx);
            pos = 0;
        }

        buf[i++] ^= aes->encr_bfr[pos++];
    }

    aes->encr_pos = pos;
    return MZ_OK;
}

int32_t mz_stream_aes_read(void *stream, void *buf, int32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    int32_t read = 0;
    read = mz_stream_read(aes->stream.base, buf, size);
    if (read > 0)
    {
        hmac_sha_data((uint8_t *)buf, (uint32_t)read, aes->auth_ctx);
        mz_stream_aes_encrypt_data(stream, (uint8_t *)buf, read);
    }

    aes->total_in += read;
    return read;
}

int32_t mz_stream_aes_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    int32_t written = 0;

    if (size < 0)
        return MZ_PARAM_ERROR;
    if (size > (int32_t)sizeof(aes->buffer))
        return MZ_STREAM_ERROR;

    memcpy(aes->buffer, buf, size);
    mz_stream_aes_encrypt_data(stream, (uint8_t *)aes->buffer, size);
    hmac_sha_data((uint8_t *)aes->buffer, (uint32_t)size, aes->auth_ctx);

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
    uint8_t authcode[MZ_AES_AUTHCODE_SIZE];
    uint8_t verify_authcode[MZ_AES_AUTHCODE_SIZE];

    if (MZ_AES_MAC_LENGTH(aes->encryption_mode) != MZ_AES_AUTHCODE_SIZE)
        return MZ_STREAM_ERROR;
    hmac_sha_end(authcode, MZ_AES_MAC_LENGTH(aes->encryption_mode), aes->auth_ctx);

    if (aes->mode & MZ_OPEN_MODE_WRITE)
    {
        if (mz_stream_write(aes->stream.base, authcode, MZ_AES_AUTHCODE_SIZE) != MZ_AES_AUTHCODE_SIZE)
            return MZ_STREAM_ERROR;

        aes->total_out += MZ_AES_AUTHCODE_SIZE;
    }
    else if (aes->mode & MZ_OPEN_MODE_READ)
    {
        if (mz_stream_read(aes->stream.base, verify_authcode, MZ_AES_AUTHCODE_SIZE) != MZ_AES_AUTHCODE_SIZE)
            return MZ_STREAM_ERROR;

        aes->total_in += MZ_AES_AUTHCODE_SIZE;

        // If entire entry was not read this will fail
        if (memcmp(authcode, verify_authcode, MZ_AES_AUTHCODE_SIZE) != 0)
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
        break;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = aes->total_out;
        break;
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        *value = aes->max_total_in;
        break;
    case MZ_STREAM_PROP_HEADER_SIZE:
        *value = MZ_AES_SALT_LENGTH((int64_t)aes->encryption_mode) + MZ_AES_PW_VERIFY_SIZE;
        break;
    case MZ_STREAM_PROP_FOOTER_SIZE:
        *value = MZ_AES_AUTHCODE_SIZE;
        break;
    default:
        return MZ_EXIST_ERROR;
    }
    return MZ_OK;
}

int32_t mz_stream_aes_set_prop_int64(void *stream, int32_t prop, int64_t value)
{
    mz_stream_aes *aes = (mz_stream_aes *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        aes->max_total_in = value;
        break;
    default:
        return MZ_EXIST_ERROR;
    }
    return MZ_OK;
}

void *mz_stream_aes_create(void **stream)
{
    mz_stream_aes *aes = NULL;

    aes = (mz_stream_aes *)MZ_ALLOC(sizeof(mz_stream_aes));
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
        MZ_FREE(aes);
    *stream = NULL;
}

void *mz_stream_aes_get_interface(void)
{
    return (void *)&mz_stream_aes_vtbl;
}

/***************************************************************************/

static mz_stream_vtbl mz_stream_sha1_vtbl = {
    mz_stream_sha1_open,
    mz_stream_sha1_is_open,
    mz_stream_sha1_read,
    mz_stream_sha1_write,
    mz_stream_sha1_tell,
    mz_stream_sha1_seek,
    mz_stream_sha1_close,
    mz_stream_sha1_error,
    mz_stream_sha1_create,
    mz_stream_sha1_delete,
    mz_stream_sha1_get_prop_int64,
    NULL
};

/***************************************************************************/

typedef struct mz_stream_sha1_s {
    mz_stream       stream;
    int32_t         mode;
    int32_t         error;
    int16_t         initialized;
    int64_t         total_in;
    int64_t         total_out;
    sha1_ctx        hash_ctx;
    uint8_t         hash[SHA1_DIGEST_SIZE];
} mz_stream_sha1;

/***************************************************************************/

int32_t mz_stream_sha1_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;

    sha1->total_in = 0;
    sha1->total_out = 0;
    sha1->initialized = 1;

    memset(sha1->hash, 0, sizeof(sha1->hash));

    sha1_begin(&sha1->hash_ctx);
    return MZ_OK;
}

int32_t mz_stream_sha1_is_open(void *stream)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    if (sha1->initialized == 0)
        return MZ_STREAM_ERROR;
    return MZ_OK;
}

int32_t mz_stream_sha1_read(void *stream, void *buf, int32_t size)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    int32_t read = size;
    if (sha1->stream.base)
        read = mz_stream_read(sha1->stream.base, buf, size);
    if (read > 0)
    {
        sha1_hash(buf, read, &sha1->hash_ctx);
        sha1->total_in += read;
    }
    return read;
}

int32_t mz_stream_sha1_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    int32_t written = size;

    if (size < 0)
        return MZ_PARAM_ERROR;
    if (sha1->stream.base)
        written = mz_stream_write(sha1->stream.base, buf, size);
    if (written > 0)
    {
        sha1_hash(buf, written, &sha1->hash_ctx);
        sha1->total_out += written;
    }
    return written;
}

int64_t mz_stream_sha1_tell(void *stream)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    return mz_stream_tell(sha1->stream.base);
}

int32_t mz_stream_sha1_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    return mz_stream_seek(sha1->stream.base, offset, origin);
}

int32_t mz_stream_sha1_close(void *stream)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;

    sha1_end(sha1->hash, &sha1->hash_ctx);
    sha1->initialized = 0;
    return MZ_OK;
}

int32_t mz_stream_sha1_error(void *stream)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    return sha1->error;
}

int32_t mz_stream_sha1_get_digest(void *stream, uint8_t *digest, int32_t digest_size)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    int32_t copy = digest_size;
    if (digest == NULL || copy < SHA1_DIGEST_SIZE)
        return MZ_PARAM_ERROR;
    if (copy > SHA1_DIGEST_SIZE)
        copy = SHA1_DIGEST_SIZE;
    memcpy(digest, sha1->hash, copy);
    return MZ_OK;
}

int32_t mz_stream_sha1_get_digest_size(void *stream, int32_t *digest_size)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    if (digest_size == NULL)
        return MZ_PARAM_ERROR;
    *digest_size = SHA1_DIGEST_SIZE;
    return MZ_OK;
}

int32_t mz_stream_sha1_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_sha1 *sha1 = (mz_stream_sha1 *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = sha1->total_in;
        break;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = sha1->total_out;
        break;
    default:
        return MZ_EXIST_ERROR;
    }
    return MZ_OK;
}

void *mz_stream_sha1_create(void **stream)
{
    mz_stream_sha1 *sha1 = NULL;

    sha1 = (mz_stream_sha1 *)MZ_ALLOC(sizeof(mz_stream_sha1));
    if (sha1 != NULL)
    {
        memset(sha1, 0, sizeof(mz_stream_sha1));
        sha1->stream.vtbl = &mz_stream_sha1_vtbl;
    }
    if (stream != NULL)
        *stream = sha1;

    return sha1;
}

void mz_stream_sha1_delete(void **stream)
{
    mz_stream_sha1 *sha1 = NULL;
    if (stream == NULL)
        return;
    sha1 = (mz_stream_sha1 *)*stream;
    if (sha1 != NULL)
        MZ_FREE(sha1);
    *stream = NULL;
}

void *mz_stream_sha1_get_interface(void)
{
    return (void *)&mz_stream_sha1_vtbl;
}