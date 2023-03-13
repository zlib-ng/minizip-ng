/* mz_crypt_winrt.c -- Crypto/hash functions for UWP
   part of the minizip-ng project

   Copyright (C) 2010-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_crypt.h"

#include <windows.h>
#include <bcrypt.h>

/***************************************************************************/

#define NT_SUCCESS(status) ((status) >= 0)

/***************************************************************************/

int32_t mz_crypt_rand(uint8_t *buf, int32_t size) {
    BCRYPT_ALG_HANDLE provider = NULL;
    NTSTATUS status = 0;

    status = BCryptOpenAlgorithmProvider(&provider, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, buf, size, 0);
        BCryptCloseAlgorithmProvider(provider, 0);
    }
    if (NT_SUCCESS(status))
        return size;

    return mz_os_rand(buf, size);
}

/***************************************************************************/

/* Adapted from RFC4634 and Igor Pavlov's 2010 public domain implementation */

typedef struct mz_crypt_sha224_s {
    uint8_t  buffer[64];
    uint32_t state[8];
    uint64_t count;
} mz_crypt_sha224;

/***************************************************************************/

#define rotl(x, n)  (((x) << (n)) | ((x) >> ((8 * sizeof(x)) - (n))))
#define rotr(x, n)  (((x) >> (n)) | ((x) << ((8 * sizeof(x)) - (n))))

#define Ch(x,y,z)   (z ^ (x & (y ^ z)))
#define Maj(x,y,z)  ((x & y) | (z & (x | y)))

#define S0_256(x)   (rotr(x, 2) ^ rotr(x,13) ^ rotr(x, 22))
#define S1_256(x)   (rotr(x, 6) ^ rotr(x,11) ^ rotr(x, 25))
#define s0_256(x)   (rotr(x, 7) ^ rotr(x,18) ^ (x >> 3))
#define s1_256(x)   (rotr(x,17) ^ rotr(x,19) ^ (x >> 10))

#define blk0(i)     (w[i] = buffer[i])
#define blk2(i)     (w[i&15] += s1_256(w[(i-2)&15]) + w[(i-7)&15] + s0_256(w[(i-15)&15]))

#define R(a,b,c,d,e,f,g,h,i)                                        \
    h += S1_256(e) + Ch(e,f,g) + k256[i+j] + (j?blk2(i):blk0(i));   \
    d += h; h += S0_256(a) + Maj(a, b, c)

#define RX_8(i)                 \
    R(a,b,c,d,e,f,g,h, (i));    \
    R(h,a,b,c,d,e,f,g, (i+1));  \
    R(g,h,a,b,c,d,e,f, (i+2));  \
    R(f,g,h,a,b,c,d,e, (i+3));  \
    R(e,f,g,h,a,b,c,d, (i+4));  \
    R(d,e,f,g,h,a,b,c, (i+5));  \
    R(c,d,e,f,g,h,a,b, (i+6));  \
    R(b,c,d,e,f,g,h,a, (i+7))

static const uint32_t k256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/***************************************************************************/

static void mz_crypt_sha224_init(mz_crypt_sha224 *sha) {
    sha->state[0] = 0xc1059ed8u;
    sha->state[1] = 0x367cd507u;
    sha->state[2] = 0x3070dd17u;
    sha->state[3] = 0xf70e5939u;
    sha->state[4] = 0xffc00b31u;
    sha->state[5] = 0x68581511u;
    sha->state[6] = 0x64f98fa7u;
    sha->state[7] = 0xbefa4fa4u;
    sha->count = 0;
}

static void mz_crypt_sha224_transform(uint32_t *state, const uint32_t *buffer) {
    uint32_t w[16];
    int32_t j = 0;
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (j = 0; j < 64; j += 16) {
        RX_8(0);
        RX_8(8);
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void mz_crypt_sha224_write_byte_block(mz_crypt_sha224 *sha) {
    uint32_t data32[16];
    int32_t i = 0;
    for (i = 0; i < 16; i++) {
        data32[i] = ((uint32_t)(sha->buffer[i * 4 + 0]) << 24) +
                    ((uint32_t)(sha->buffer[i * 4 + 1]) << 16) +
                    ((uint32_t)(sha->buffer[i * 4 + 2]) << 8 ) +
                    ((uint32_t)(sha->buffer[i * 4 + 3]));
    }
    mz_crypt_sha224_transform(sha->state, data32);
}

static void mz_crypt_sha224_update(mz_crypt_sha224 *sha, const uint8_t *data, size_t size) {
    uint32_t pos = (uint32_t)sha->count & 0x3F;
    while (size > 0) {
        sha->buffer[pos++] = *data++;
        sha->count++;
        size--;
        if (pos == 64) {
            pos = 0;
            mz_crypt_sha224_write_byte_block(sha);
        }
    }
}

static void mz_crypt_sha224_end(mz_crypt_sha224 *sha, uint8_t *digest) {
    uint64_t bits = (sha->count << 3);
    uint32_t pos = (uint32_t)sha->count & 0x3F;
    int32_t i = 0;
    sha->buffer[pos++] = 0x80;
    while (pos != (64 - 8)) {
        pos &= 0x3F;
        if (pos == 0)
            mz_crypt_sha224_write_byte_block(sha);
        sha->buffer[pos++] = 0;
    }
    for (i = 0; i < 8; i++) {
        sha->buffer[pos++] = (uint8_t)(bits >> 56);
        bits <<= 8;
    }
    mz_crypt_sha224_write_byte_block(sha);

    for (i = 0; i < 7; i++) {
        *digest++ = (uint8_t)(sha->state[i] >> 24);
        *digest++ = (uint8_t)(sha->state[i] >> 16);
        *digest++ = (uint8_t)(sha->state[i] >> 8 );
        *digest++ = (uint8_t)(sha->state[i]);
    }
    mz_crypt_sha224_init(sha);
}

/***************************************************************************/

typedef struct mz_crypt_sha_s {
    union {
        struct {
            BCRYPT_ALG_HANDLE  provider;
            BCRYPT_HASH_HANDLE hash;
            uint8_t            *buffer;
        };
        mz_crypt_sha224        *sha224;
    };
    int32_t                    error;
    uint16_t                   algorithm;
} mz_crypt_sha;

/***************************************************************************/

void mz_crypt_sha_reset(void *handle) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    if (sha->algorithm == MZ_HASH_SHA224) {
        free(sha->sha224);
        sha->sha224 = NULL;
    } else {
        if (sha->hash)
            BCryptDestroyHash(sha->hash);
        if (sha->provider)
            BCryptCloseAlgorithmProvider(sha->provider, 0);
        free(sha->buffer);
        sha->hash = NULL;
        sha->provider = NULL;
        sha->buffer = NULL;
    }
    sha->error = 0;
}

int32_t mz_crypt_sha_begin(void *handle) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    NTSTATUS status = 0;
    const wchar_t *alg_id = BCRYPT_SHA256_ALGORITHM;
    ULONG buffer_size = 0;
    ULONG result_size = sizeof(buffer_size);
    int32_t err = MZ_OK;

    if (!sha)
        return MZ_PARAM_ERROR;

    if (sha->algorithm == MZ_HASH_SHA224) {
        sha->sha224 = malloc(sizeof(mz_crypt_sha224));
        if (!sha->sha224)
            return MZ_MEM_ERROR;
        mz_crypt_sha224_init(sha->sha224);
        return MZ_OK;
    }

    switch (sha->algorithm) {
    case MZ_HASH_SHA1:
        alg_id = BCRYPT_SHA1_ALGORITHM;
        break;
    case MZ_HASH_SHA384:
        alg_id = BCRYPT_SHA384_ALGORITHM;
        break;
    case MZ_HASH_SHA512:
        alg_id = BCRYPT_SHA512_ALGORITHM;
        break;
    }

    status = BCryptOpenAlgorithmProvider(&sha->provider, alg_id, NULL, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptGetProperty(sha->provider, BCRYPT_OBJECT_LENGTH, (PUCHAR)&buffer_size, result_size, &result_size,
            0);
    }
    if (NT_SUCCESS(status)) {
        sha->buffer = malloc(buffer_size);
        if (!sha->buffer)
            return MZ_MEM_ERROR;
        status = BCryptCreateHash(sha->provider, &sha->hash, sha->buffer, buffer_size, NULL, 0, 0);
    }
    if (!NT_SUCCESS(status)) {
        sha->error = status;
        err = MZ_HASH_ERROR;
    }

    return err;
}

int32_t mz_crypt_sha_update(void *handle, const void *buf, int32_t size) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    NTSTATUS status = 0;

    if (!sha || !buf || size < 0)
        return MZ_PARAM_ERROR;

    if (sha->algorithm == MZ_HASH_SHA224) {
        if (!sha->sha224)
            return MZ_PARAM_ERROR;
        mz_crypt_sha224_update(sha->sha224, buf, size);
        return size;
    }

    if (sha->hash == 0)
        return MZ_PARAM_ERROR;

    status = BCryptHashData(sha->hash, (uint8_t*)buf, size, 0);
    if (!NT_SUCCESS(status)) {
        sha->error = status;
        return MZ_HASH_ERROR;
    }
    return size;
}

int32_t mz_crypt_sha_end(void *handle, uint8_t *digest, int32_t digest_size) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    NTSTATUS status = 0;
    ULONG expected_size = 0;
    ULONG result_size = sizeof(expected_size);

    if (!sha || !digest)
        return MZ_PARAM_ERROR;

    if (sha->algorithm == MZ_HASH_SHA224) {
        if (!sha->sha224 || digest_size < 28)
            return MZ_PARAM_ERROR;
        mz_crypt_sha224_end(sha->sha224, digest);
        return MZ_OK;
    }

    if (sha->hash == 0)
        return MZ_PARAM_ERROR;

    status = BCryptGetProperty(sha->hash, BCRYPT_HASH_LENGTH, (PUCHAR)&expected_size, result_size, &result_size, 0);
    if (!NT_SUCCESS(status))
        return MZ_HASH_ERROR;
    if ((int32_t)expected_size > digest_size)
        return MZ_BUF_ERROR;
    status = BCryptFinishHash(sha->hash, digest, expected_size, 0);
    if (!NT_SUCCESS(status)) {
        sha->error = status;
        return MZ_HASH_ERROR;
    }
    return MZ_OK;
}

void mz_crypt_sha_set_algorithm(void *handle, uint16_t algorithm) {
    mz_crypt_sha *sha = (mz_crypt_sha *)handle;
    sha->algorithm = algorithm;
}

void *mz_crypt_sha_create(void **handle) {
    mz_crypt_sha *sha = NULL;

    sha = (mz_crypt_sha *)malloc(sizeof(mz_crypt_sha));
    if (sha) {
        memset(sha, 0, sizeof(mz_crypt_sha));
        sha->algorithm = MZ_HASH_SHA256;
    }
    if (handle)
        *handle = sha;

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
    BCRYPT_ALG_HANDLE provider;
    BCRYPT_KEY_HANDLE key;
    uint8_t           *key_buffer;
    int32_t           mode;
    int32_t           error;
} mz_crypt_aes;

/***************************************************************************/

static void mz_crypt_aes_free(void *handle) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    if (aes->key)
        BCryptDestroyKey(aes->key);
    if (aes->provider)
        BCryptCloseAlgorithmProvider(aes->provider, 0);
    free(aes->key_buffer);
    aes->provider = NULL;
    aes->key = NULL;
    aes->key_buffer = NULL;
}

void mz_crypt_aes_reset(void *handle) {
    mz_crypt_aes_free(handle);
}

int32_t mz_crypt_aes_encrypt(void *handle, uint8_t *buf, int32_t size) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    ULONG output_size = 0;
    NTSTATUS status = 0;
    if (!aes || !buf)
        return MZ_PARAM_ERROR;
    if (size != MZ_AES_BLOCK_SIZE)
        return MZ_PARAM_ERROR;
    status = BCryptEncrypt(aes->key, buf, size, NULL, NULL, 0, buf, size, &output_size, 0);
    if (!NT_SUCCESS(status)) {
        aes->error = status;
        return MZ_CRYPT_ERROR;
    }
    return size;
}

int32_t mz_crypt_aes_decrypt(void *handle, uint8_t *buf, int32_t size) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    ULONG output_size = 0;
    NTSTATUS status = 0;
    if (!aes || !buf)
        return MZ_PARAM_ERROR;
    if (size != MZ_AES_BLOCK_SIZE)
        return MZ_PARAM_ERROR;
    status = BCryptDecrypt(aes->key, buf, size, NULL, NULL, 0, buf, size, &output_size, 0);
    if (!NT_SUCCESS(status)) {
        aes->error = status;
        return MZ_CRYPT_ERROR;
    }
    return size;
}

static int32_t mz_crypt_aes_set_key(void *handle, const void *key, int32_t key_length) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    BCRYPT_KEY_DATA_BLOB_HEADER *key_blob = NULL;
    int32_t key_blob_size = 0;
    ULONG key_size;
    ULONG result_size = sizeof(key_size);
    NTSTATUS status = 0;
    int32_t err = MZ_OK;

    if (!aes || !key || !key_length)
        return MZ_PARAM_ERROR;

    mz_crypt_aes_reset(handle);

    if (key_length != MZ_AES_KEY_LENGTH(MZ_AES_ENCRYPTION_MODE_128) &&
        key_length != MZ_AES_KEY_LENGTH(MZ_AES_ENCRYPTION_MODE_192) &&
        key_length != MZ_AES_KEY_LENGTH(MZ_AES_ENCRYPTION_MODE_256)) {
        return MZ_PARAM_ERROR;
    }

    status = BCryptOpenAlgorithmProvider(&aes->provider, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (NT_SUCCESS(status)) {
        status = BCryptGetProperty(aes->provider, BCRYPT_OBJECT_LENGTH, (PUCHAR)&key_size, result_size, &result_size,
            0);
    }
    if (NT_SUCCESS(status)) {
        status = BCryptSetProperty(aes->provider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC,
            sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    }
    if (NT_SUCCESS(status)) {
        aes->key_buffer = malloc(key_size);
        if (!aes->key_buffer)
            return MZ_MEM_ERROR;
        key_blob_size = sizeof(*key_blob) + key_length;
        key_blob = malloc(key_blob_size);
        if (key_blob) {
            key_blob->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
            key_blob->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
            key_blob->cbKeyData = key_length;

            memcpy((uint8_t*)key_blob + sizeof(*key_blob), key, key_length);

            status = BCryptImportKey(aes->provider, NULL, BCRYPT_KEY_DATA_BLOB, &aes->key, aes->key_buffer, key_size,
                (PUCHAR)key_blob, key_blob_size, 0);
            SecureZeroMemory(key_blob, key_blob_size);
            free(key_blob);
        }
    }
    if (!NT_SUCCESS(status)) {
        aes->error = status;
        err = MZ_CRYPT_ERROR;
    }
    return err;
}

int32_t mz_crypt_aes_set_encrypt_key(void *handle, const void *key, int32_t key_length) {
    return mz_crypt_aes_set_key(handle, key, key_length);
}

int32_t mz_crypt_aes_set_decrypt_key(void *handle, const void *key, int32_t key_length) {
    return mz_crypt_aes_set_key(handle, key, key_length);
}

void mz_crypt_aes_set_mode(void *handle, int32_t mode) {
    mz_crypt_aes *aes = (mz_crypt_aes *)handle;
    aes->mode = mode;
}

void *mz_crypt_aes_create(void **handle) {
    mz_crypt_aes *aes = NULL;

    aes = (mz_crypt_aes *)calloc(1, sizeof(mz_crypt_aes));
    if (handle)
        *handle = aes;

    return aes;
}

void mz_crypt_aes_delete(void **handle) {
    mz_crypt_aes *aes = NULL;
    if (!handle)
        return;
    aes = (mz_crypt_aes *)*handle;
    if (aes) {
        mz_crypt_aes_free(*handle);
        free(aes);
    }
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_crypt_hmac_s {
    BCRYPT_ALG_HANDLE  provider;
    BCRYPT_KEY_HANDLE  key;
    BCRYPT_HASH_HANDLE hash;
    uint8_t            *buffer;
    int32_t            error;
    uint16_t           algorithm;
} mz_crypt_hmac;

/***************************************************************************/

static void mz_crypt_hmac_free(void *handle) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    if (hmac->hash)
        BCryptDestroyHash(hmac->hash);
    if (hmac->key)
        BCryptDestroyKey(hmac->key);
    if (hmac->provider)
        BCryptCloseAlgorithmProvider(hmac->provider, 0);
    free(hmac->buffer);
    hmac->hash = NULL;
    hmac->key = NULL;
    hmac->provider = NULL;
    hmac->buffer = NULL;
}

void mz_crypt_hmac_reset(void *handle) {
    mz_crypt_hmac_free(handle);
}

int32_t mz_crypt_hmac_init(void *handle, const void *key, int32_t key_length) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    wchar_t *alg_id = BCRYPT_SHA256_ALGORITHM;
    ULONG buffer_size = 0;
    ULONG result_size = sizeof(buffer_size);
    NTSTATUS status = 0;
    int32_t err = MZ_OK;

    if (!hmac || !key)
        return MZ_PARAM_ERROR;

    mz_crypt_hmac_reset(handle);

    if (hmac->algorithm == MZ_HASH_SHA1)
        alg_id = BCRYPT_SHA1_ALGORITHM;

    status = BCryptOpenAlgorithmProvider(&hmac->provider, alg_id, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (NT_SUCCESS(status)) {
        status = BCryptGetProperty(hmac->provider, BCRYPT_OBJECT_LENGTH, (PUCHAR)&buffer_size, result_size,
            &result_size, 0);
    }
    if (NT_SUCCESS(status)) {
        hmac->buffer = malloc(buffer_size);
        if (!hmac->buffer)
            return MZ_MEM_ERROR;
    }
    if (NT_SUCCESS(status))
        status = BCryptCreateHash(hmac->provider, &hmac->hash, hmac->buffer, buffer_size, (PUCHAR)key, key_length, 0);

    if (!NT_SUCCESS(status)) {
        hmac->error = status;
        err = MZ_CRYPT_ERROR;
    }

    if (err != MZ_OK)
        mz_crypt_hmac_free(handle);

    return err;
}

int32_t mz_crypt_hmac_update(void *handle, const void *buf, int32_t size) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    NTSTATUS status = 0;

    if (!hmac || !buf || !hmac->hash)
        return MZ_PARAM_ERROR;

    status = BCryptHashData(hmac->hash, (uint8_t*)buf, size, 0);
    if (!NT_SUCCESS(status)) {
        hmac->error = status;
        return MZ_HASH_ERROR;
    }
    return MZ_OK;
}

int32_t mz_crypt_hmac_end(void *handle, uint8_t *digest, int32_t digest_size) {
    mz_crypt_hmac *hmac = (mz_crypt_hmac *)handle;
    NTSTATUS status = 0;
    ULONG expected_size = 0;
    ULONG result_size = sizeof(expected_size);

    if (!hmac || !digest || !hmac->hash)
        return MZ_PARAM_ERROR;
    status = BCryptGetProperty(hmac->hash, BCRYPT_HASH_LENGTH, (PUCHAR)&expected_size, result_size, &result_size, 0);
    if (!NT_SUCCESS(status))
        return MZ_HASH_ERROR;
    if ((int32_t)expected_size > digest_size)
        return MZ_BUF_ERROR;
    status = BCryptFinishHash(hmac->hash, digest, expected_size, 0);
    if (!NT_SUCCESS(status)) {
        hmac->error = status;
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
    NTSTATUS status = 0;
    int32_t err = MZ_OK;

    if (target->hash) {
        BCryptDestroyHash(target->hash);
        target->hash = NULL;
    }

    status = BCryptDuplicateHash(source->hash, &target->hash, NULL, 0, 0);

    if (!NT_SUCCESS(status)) {
        target->error = status;
        err = MZ_HASH_ERROR;
    }
    return err;
}

void *mz_crypt_hmac_create(void **handle) {
    mz_crypt_hmac *hmac = NULL;

    hmac = (mz_crypt_hmac *)calloc(1, sizeof(mz_crypt_hmac));
    if (hmac)
        hmac->algorithm = MZ_HASH_SHA256;
    if (handle)
        *handle = hmac;

    return hmac;
}

void mz_crypt_hmac_delete(void **handle) {
    mz_crypt_hmac *hmac = NULL;
    if (!handle)
        return;
    hmac = (mz_crypt_hmac *)*handle;
    if (hmac) {
        mz_crypt_hmac_free(*handle);
        free(hmac);
    }
    *handle = NULL;
}

/***************************************************************************/

#if defined(MZ_ZIP_SIGNING)
int32_t mz_crypt_sign(uint8_t *message, int32_t message_size, uint8_t *cert_data, int32_t cert_data_size,
    const char *cert_pwd, uint8_t **signature, int32_t *signature_size) {
    return MZ_SIGN_ERROR;
#if 0
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE private_key = 0;
    uint32_t private_key_spec = 0;
    BOOL release_private_key = FALSE;
    CRYPT_DATA_BLOB cert_data_blob;
    PCCERT_CONTEXT cert_context = NULL;
    HCERTSTORE cert_store = 0;
    BCRYPT_PKCS1_PADDING_INFO pad_info;
    wchar_t *password_wide = NULL;
    int32_t result = 0;
    int32_t err = MZ_OK;

    if (!message || !cert_data || !signature || !signature_size)
        return MZ_PARAM_ERROR;

    *signature = NULL;
    *signature_size = 0;

    pad_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
    cert_data_blob.pbData = cert_data;
    cert_data_blob.cbData = cert_data_size;

    password_wide = mz_os_unicode_string_create(cert_pwd, MZ_ENCODING_UTF8);
    if (password_wide) {
        cert_store = PFXImportCertStore(&cert_data_blob, password_wide, 0);
        mz_os_unicode_string_delete(&password_wide);
    }

    if (!cert_store)
        cert_store = PFXImportCertStore(&cert_data_blob, L"", 0);
    if (!cert_store)
        cert_store = PFXImportCertStore(&cert_data_blob, NULL, 0);
    if (!cert_store)
        return MZ_PARAM_ERROR;

    if (err == MZ_OK) {
        cert_context = CertFindCertificateInStore(cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
        if (!cert_context)
            err = MZ_PARAM_ERROR;
    }
    if (err == MZ_OK) {
        if (!CryptAcquireCertificatePrivateKey(cert_context, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, NULL, &private_key,
            &private_key_spec, &release_private_key)) {
            err = MZ_PARAM_ERROR;
        }
    }
    if (err == MZ_OK) {

#if 0 /* Timestamp support */
        CRYPT_ATTR_BLOB crypt_blob;
        CRYPT_TIMESTAMP_CONTEXT *ts_context = NULL;
        CRYPT_ATTRIBUTE unauth_attribs[1];
        wchar_t *timestamp_url_wide = NULL;
        const char *timestamp_url = NULL;

        if (timestamp_url)
            timestamp_url_wide = mz_os_unicode_string_create(timestamp_url);
        if (timestamp_url_wide) {
            result = CryptRetrieveTimeStamp(timestamp_url_wide,
                TIMESTAMP_NO_AUTH_RETRIEVAL | TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, 0, szOID_NIST_sha256,
                NULL, message, message_size, &ts_context, NULL, NULL);

            mz_os_unicode_string_delete(&timestamp_url_wide);

            if (result && ts_context) {
                crypt_blob.cbData = ts_context->cbEncoded;
                crypt_blob.pbData = ts_context->pbEncoded;

                unauth_attribs[0].pszObjId = "1.2.840.113549.1.9.16.2.14"; //id-smime-aa-timeStampToken
                unauth_attribs[0].cValue = 1;
                unauth_attribs[0].rgValue = &crypt_blob;

                sign_params.rgUnauthAttr = &unauth_attribs[0];
                sign_params.cUnauthAttr = 1;
            }
        }

        if (ts_context)
            CryptMemFree(ts_context);

        if (result)
#endif
            result = !NCryptSignHash(private_key, &pad_info, message, message_size, NULL, 0, signature_size,
                BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG);

        if (result && *signature_size > 0)
            *signature = (uint8_t *)malloc(*signature_size);

        if (result && *signature) {
            result = !NCryptSignHash(private_key, &pad_info, message, message_size, *signature, *signature_size,
                signature_size, BCRYPT_PAD_PKCS1 | NCRYPT_SILENT_FLAG);
        }

        if (release_private_key) {
            if (private_key_spec == CERT_NCRYPT_KEY_SPEC)
                NCryptFreeObject(private_key);
            else
                CryptReleaseContext(private_key, 0);
        }

        if (!result)
            err = MZ_SIGN_ERROR;
    }

    if (cert_context)
        CertFreeCertificateContext(cert_context);
    if (cert_store)
        CertCloseStore(cert_store, 0);
    return err;
    #endif
}

int32_t mz_crypt_sign_verify(uint8_t *message, int32_t message_size, uint8_t *signature, int32_t signature_size) {
    return MZ_SIGN_ERROR;
#if 0
    CRYPT_VERIFY_MESSAGE_PARA verify_params;
    CERT_CONTEXT *signer_cert = NULL;
    CERT_CHAIN_PARA  chain_para;
    CERT_CHAIN_CONTEXT *chain_context = NULL;
    CERT_CHAIN_POLICY_PARA chain_policy;
    CERT_CHAIN_POLICY_STATUS chain_policy_status;
    HCRYPTMSG crypt_msg = 0;
    int32_t result = 0;
    int32_t err = MZ_SIGN_ERROR;
    uint8_t *decoded = NULL;
    int32_t decoded_size = 0;

    memset(&verify_params, 0, sizeof(verify_params));

    verify_params.cbSize = sizeof(verify_params);
    verify_params.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    result = CryptVerifyMessageSignature(&verify_params, 0, signature, signature_size,
        NULL, (DWORD *)&decoded_size, NULL);

    if (result && decoded_size > 0)
        decoded = (uint8_t *)malloc(decoded_size);

    if (result && decoded)
        result = CryptVerifyMessageSignature(&verify_params, 0, signature, signature_size,
            decoded, (DWORD *)&decoded_size, (const CERT_CONTEXT **)&signer_cert);

    /* Get and validate certificate chain */
    memset(&chain_para, 0, sizeof(chain_para));

    if (result && signer_cert)
        result = CertGetCertificateChain(NULL, signer_cert, NULL, NULL, &chain_para,
            CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, NULL, (const CERT_CHAIN_CONTEXT **)&chain_context);

    memset(&chain_policy, 0, sizeof(chain_policy));
    chain_policy.cbSize = sizeof(CERT_CHAIN_POLICY_PARA);

    memset(&chain_policy_status, 0, sizeof(chain_policy_status));
    chain_policy_status.cbSize = sizeof(CERT_CHAIN_POLICY_STATUS);

    if (result && chain_context)
        result = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, chain_context,
            &chain_policy, &chain_policy_status);

    if (chain_policy_status.dwError != S_OK)
        result = 0;

#if 0
    crypt_msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    if (crypt_msg) {
        /* Timestamp support */
        PCRYPT_ATTRIBUTES unauth_attribs = NULL;
        HCRYPTMSG ts_msg = 0;
        uint8_t *ts_content = NULL;
        int32_t ts_content_size = 0;
        uint8_t *ts_signature = NULL;
        int32_t ts_signature_size = 0;

        result = CryptMsgUpdate(crypt_msg, signature, signature_size, 1);

        if (result)
            CryptMsgGetParam(crypt_msg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &ts_signature_size);

        if (result && ts_signature_size > 0)
            ts_signature = (uint8_t *)malloc(ts_signature_size);

        if (result && ts_signature) {
            result = CryptMsgGetParam(crypt_msg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, ts_signature,
                &ts_signature_size);
            if (result)
            {
                unauth_attribs = (PCRYPT_ATTRIBUTES)ts_signature;

                if ((unauth_attribs->cAttr > 0) && (unauth_attribs->rgAttr[0].cValue > 0))
                {
                    ts_content = unauth_attribs->rgAttr[0].rgValue->pbData;
                    ts_content_size = unauth_attribs->rgAttr[0].rgValue->cbData;
                }
            }

            if (result && ts_content)
                result = CryptVerifyTimeStampSignature(ts_content, ts_content_size, decoded,
                    decoded_size, 0, &crypt_context, NULL, NULL);

            if (result)
                err = MZ_OK;
        }

        if (ts_signature)
            free(ts_signature);

        if (crypt_context)
            CryptMemFree(crypt_context);
    } else {
        result = 0;
    }
#endif

    if (result && decoded && decoded_size == message_size) {
        /* Verify cms message with our stored message */
        if (memcmp(decoded, message, message_size) == 0)
            err = MZ_OK;
    }

    if (chain_context)
        CertFreeCertificateChain(chain_context);
    if (signer_cert)
        CertFreeCertificateContext(signer_cert);
    if (crypt_msg)
        CryptMsgClose(crypt_msg);

    if (decoded)
        free(decoded);

    return err;
#endif
}
#endif
