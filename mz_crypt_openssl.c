/* mz_crypt_openssl.c -- Crypto/hash functions for OpenSSL
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"

#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#if defined(MZ_ZIP_SIGNING)
/* Note: https://www.imperialviolet.org/2015/10/17/boringssl.html says that
   BoringSSL does not support CMS. "#include <etc/cms.h>" will fail. See
   https://bugs.chromium.org/p/boringssl/issues/detail?id=421
*/
#include <openssl/cms.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#endif

/***************************************************************************/

static void mz_crypt_init(void) {
    static int32_t openssl_initialized = 0;
    if (!openssl_initialized) {
        OpenSSL_add_all_algorithms();

        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();

        openssl_initialized = 1;
    }
}

int32_t mz_crypt_rand(uint8_t *buf, int32_t size) {
    int32_t result = 0;

    result = RAND_bytes(buf, size);

    if (!result)
        return MZ_CRYPT_ERROR;

    return size;
}

/***************************************************************************/

typedef struct mz_crypt_sha_s {
    union {
        SHA512_CTX ctx512;
        SHA256_CTX ctx256;
        SHA_CTX    ctx1;
    };
    int32_t        initialized;
    int32_t        error;
    uint16_t       algorithm;
} mz_crypt_sha;

/***************************************************************************/

static const uint8_t mz_crypt_sha_digest_size[] = {
    MZ_HASH_SHA1_SIZE,                     0, MZ_HASH_SHA224_SIZE,
    MZ_HASH_SHA256_SIZE, MZ_HASH_SHA384_SIZE, MZ_HASH_SHA512_SIZE
};

/***************************************************************************/

void mz_crypt_sha_reset(void *handle) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;

    sha->error = 0;
    sha->initialized = 0;

    mz_crypt_init();
}

int32_t mz_crypt_sha_begin(void *handle) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    int32_t result = 0;

    if (!sha)
        return MZ_PARAM_ERROR;

    mz_crypt_sha_reset(handle);

    switch (sha->algorithm) {
    case MZ_HASH_SHA1:
        result = SHA1_Init(&sha->ctx1);
        break;
    case MZ_HASH_SHA224:
        result = SHA224_Init(&sha->ctx256);
        break;
    case MZ_HASH_SHA256:
        result = SHA256_Init(&sha->ctx256);
        break;
    case MZ_HASH_SHA384:
        result = SHA384_Init(&sha->ctx512);
        break;
    case MZ_HASH_SHA512:
        result = SHA512_Init(&sha->ctx512);
        break;
    }

    if (!result) {
        sha->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    sha->initialized = 1;
    return MZ_OK;
}

int32_t mz_crypt_sha_update(void *handle, const void *buf, int32_t size) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    int32_t result = 0;

    if (!sha || !buf || !sha->initialized)
        return MZ_PARAM_ERROR;

    switch (sha->algorithm) {
    case MZ_HASH_SHA1:
        result = SHA1_Update(&sha->ctx1, buf, size);
        break;
    case MZ_HASH_SHA224:
        result = SHA224_Update(&sha->ctx256, buf, size);
        break;
    case MZ_HASH_SHA256:
        result = SHA256_Update(&sha->ctx256, buf, size);
        break;
    case MZ_HASH_SHA384:
        result = SHA384_Update(&sha->ctx512, buf, size);
        break;
    case MZ_HASH_SHA512:
        result = SHA512_Update(&sha->ctx512, buf, size);
        break;
    }

    if (!result) {
        sha->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return size;
}

int32_t mz_crypt_sha_end(void *handle, uint8_t *digest, int32_t digest_size) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    int32_t result = 0;

    if (!sha || !digest || !sha->initialized)
        return MZ_PARAM_ERROR;
    if (digest_size < mz_crypt_sha_digest_size[sha->algorithm - MZ_HASH_SHA1])
        return MZ_PARAM_ERROR;

    switch (sha->algorithm) {
    case MZ_HASH_SHA1:
        result = SHA1_Final(digest, &sha->ctx1);
        break;
    case MZ_HASH_SHA224:
        result = SHA224_Final(digest, &sha->ctx256);
        break;
    case MZ_HASH_SHA256:
        result = SHA256_Final(digest, &sha->ctx256);
        break;
    case MZ_HASH_SHA384:
        result = SHA384_Final(digest, &sha->ctx512);
        break;
    case MZ_HASH_SHA512:
        result = SHA512_Final(digest, &sha->ctx512);
        break;
    }

    if (!result) {
        sha->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

void mz_crypt_sha_set_algorithm(void *handle, uint16_t algorithm) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    if (MZ_HASH_SHA1 <= algorithm && algorithm <= MZ_HASH_SHA512)
        sha->algorithm = algorithm;
}

void *mz_crypt_sha_create(void) {
    mz_crypt_sha *sha = (mz_crypt_sha *)calloc(1, sizeof(mz_crypt_sha));
    if (sha)
        sha->algorithm = MZ_HASH_SHA256;
    return sha;
}

void mz_crypt_sha_delete(void **handle) {
    mz_crypt_sha *sha = NULL;
    if (!handle)
        return;
    sha = (mz_crypt_sha *)*handle;
    if (sha) {
        mz_crypt_sha_reset(*handle);
        free(sha);
    }
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_crypt_aes_s {
    AES_KEY    key;
    int32_t    mode;
    int32_t    error;
    uint8_t    *key_copy;
    int32_t    key_length;
    uint8_t    iv[MZ_AES_BLOCK_SIZE];
} mz_crypt_aes;

/***************************************************************************/

void mz_crypt_aes_reset(void *handle) {
    MZ_UNUSED(handle);

    mz_crypt_init();
}

int32_t mz_crypt_aes_encrypt(void *handle, uint8_t *buf, int32_t size) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;

    if (!aes || !buf || size != MZ_AES_BLOCK_SIZE)
        return MZ_PARAM_ERROR;

    if (aes->mode == MZ_AES_MODE_CBC)
        AES_cbc_encrypt(buf, buf, size, &aes->key, aes->iv, AES_ENCRYPT);
    else if (aes->mode == MZ_AES_MODE_ECB) {
        while (size) {
            AES_ecb_encrypt(buf, buf, &aes->key, AES_ENCRYPT);

            buf += MZ_AES_BLOCK_SIZE;
            size -= MZ_AES_BLOCK_SIZE;
        }
    } else
        return MZ_PARAM_ERROR;

    return size;
}

int32_t mz_crypt_aes_decrypt(void *handle, uint8_t *buf, int32_t size) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;

    if (!aes || !buf || size != MZ_AES_BLOCK_SIZE)
        return MZ_PARAM_ERROR;

    if (aes->mode == MZ_AES_MODE_CBC)
        AES_cbc_encrypt(buf, buf, size, &aes->key, aes->iv, AES_DECRYPT);
    else if (aes->mode == MZ_AES_MODE_ECB) {
        while (size) {
            AES_ecb_encrypt(buf, buf, &aes->key, AES_DECRYPT);

            buf += MZ_AES_BLOCK_SIZE;
            size -= MZ_AES_BLOCK_SIZE;
        }
    } else
        return MZ_PARAM_ERROR;

    return size;
}

int32_t mz_crypt_aes_set_encrypt_key(void *handle, const void *key, int32_t key_length) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    int32_t result = 0;
    int32_t key_bits = 0;

    if (!aes || !key || !key_length)
        return MZ_PARAM_ERROR;
    if (key_length != 16 && key_length != 24 && key_length != 32)
        return MZ_PARAM_ERROR;

    mz_crypt_aes_reset(handle);

    key_bits = key_length * 8;
    result = AES_set_encrypt_key(key, key_bits, &aes->key);
    if (result) {
        aes->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

int32_t mz_crypt_aes_set_decrypt_key(void *handle, const void *key, int32_t key_length) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    int32_t result = 0;
    int32_t key_bits = 0;

    if (!aes || !key || !key_length)
        return MZ_PARAM_ERROR;
    if (key_length != 16 && key_length != 24 && key_length != 32)
        return MZ_PARAM_ERROR;

    mz_crypt_aes_reset(handle);

    key_bits = key_length * 8;
    result = AES_set_decrypt_key(key, key_bits, &aes->key);
    if (result) {
        aes->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

int32_t mz_crypt_aes_set_iv(void *handle, const uint8_t *iv, int32_t iv_length) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    if (!aes || !iv || iv_length != MZ_AES_BLOCK_SIZE)
        return MZ_PARAM_ERROR;
    memcpy(aes->iv, iv, iv_length);
    return MZ_OK;
}

void mz_crypt_aes_set_mode(void *handle, int32_t mode) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    aes->mode = mode;
}

void *mz_crypt_aes_create(void) {
    mz_crypt_aes *aes = (mz_crypt_aes *)calloc(1, sizeof(mz_crypt_aes));
    return aes;
}

void mz_crypt_aes_delete(void **handle) {
    mz_crypt_aes *aes = NULL;
    if (!handle)
        return;
    aes = (mz_crypt_aes *)*handle;
    if (aes)
        free(aes);
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_crypt_hmac_s {
    HMAC_CTX   *ctx;
    int32_t    initialized;
    int32_t    error;
    uint16_t   algorithm;
} mz_crypt_hmac;

/***************************************************************************/

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || (defined(LIBRESSL_VERSION_NUMBER) && (LIBRESSL_VERSION_NUMBER < 0x2070000fL))
static HMAC_CTX *HMAC_CTX_new(void) {
    HMAC_CTX *ctx = OPENSSL_malloc(sizeof(HMAC_CTX));
    if (ctx)
        HMAC_CTX_init(ctx);
    return ctx;
}

static void HMAC_CTX_free(HMAC_CTX *ctx) {
    if (ctx) {
        HMAC_CTX_cleanup(ctx);
        OPENSSL_free(ctx);
    }
}
#endif

/***************************************************************************/

void mz_crypt_hmac_reset(void *handle) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;

    HMAC_CTX_free(hmac->ctx);

    hmac->ctx = NULL;
    hmac->error = 0;

    mz_crypt_init();
}

int32_t mz_crypt_hmac_init(void *handle, const void *key, int32_t key_length) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    int32_t result = 0;
    const EVP_MD *evp_md = NULL;

    if (!hmac || !key)
        return MZ_PARAM_ERROR;

    mz_crypt_hmac_reset(handle);

    hmac->ctx = HMAC_CTX_new();

    if (hmac->algorithm == MZ_HASH_SHA1)
        evp_md = EVP_sha1();
    else
        evp_md = EVP_sha256();

    result = HMAC_Init_ex(hmac->ctx, key, key_length, evp_md, NULL);
    if (!result) {
        hmac->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

int32_t mz_crypt_hmac_update(void *handle, const void *buf, int32_t size) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    int32_t result = 0;

    if (!hmac || !buf)
        return MZ_PARAM_ERROR;

    result = HMAC_Update(hmac->ctx, buf, size);
    if (!result) {
        hmac->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

int32_t mz_crypt_hmac_end(void *handle, uint8_t *digest, int32_t digest_size) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    int32_t result = 0;

    if (!hmac || !digest)
        return MZ_PARAM_ERROR;

    if (hmac->algorithm == MZ_HASH_SHA1) {
        if (digest_size < MZ_HASH_SHA1_SIZE)
            return MZ_BUF_ERROR;

        result = HMAC_Final(hmac->ctx, digest, (uint32_t *)&digest_size);
    } else {
        if (digest_size < MZ_HASH_SHA256_SIZE)
            return MZ_BUF_ERROR;
        result = HMAC_Final(hmac->ctx, digest, (uint32_t *)&digest_size);
    }

    if (!result) {
        hmac->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

void mz_crypt_hmac_set_algorithm(void *handle, uint16_t algorithm) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    hmac->algorithm = algorithm;
}

int32_t mz_crypt_hmac_copy(void *src_handle, void *target_handle) {
    mz_crypt_hmac *source = (mz_crypt_hmac *)src_handle;
    mz_crypt_hmac *target = (mz_crypt_hmac *)target_handle;
    int32_t result = 0;

    if (!source || !target)
        return MZ_PARAM_ERROR;

    mz_crypt_hmac_reset(target_handle);

    if (!target->ctx)
        target->ctx = HMAC_CTX_new();

    result = HMAC_CTX_copy(target->ctx, source->ctx);
    if (!result) {
        target->error = ERR_get_error();
        return MZ_HASH_ERROR;
    }

    return MZ_OK;
}

void *mz_crypt_hmac_create(void) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)calloc(1, sizeof(mz_crypt_hmac));
    if (hmac)
        hmac->algorithm = MZ_HASH_SHA256;
    return hmac;
}

void mz_crypt_hmac_delete(void **handle) {
    mz_crypt_hmac *hmac = NULL;
    if (!handle)
        return;
    hmac = (mz_crypt_hmac *)*handle;
    if (hmac) {
        mz_crypt_hmac_reset(*handle);
        free(hmac);
    }
    *handle = NULL;
}
