/* test_crypt.cc - Test cryptography implementation
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_crypt.h"

#include <string>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <stdio.h> /* printf, snprintf */

#if GTEST_OS_WINDOWS
#  include <sdkddkver.h> /* _WIN32_WINNT defines */
#endif

#ifndef MZ_ZIP_NO_CRYPT_BACKEND
static const char *hash_test_string = "the quick and lazy fox did his thang";

static void convert_buffer_to_hex_string(uint8_t *buf, int32_t buf_size, char *hex_string, int32_t max_hex_string) {
    int32_t p = 0;
    int32_t i = 0;

    if (max_hex_string > 0)
        hex_string[0] = 0;
    for (i = 0, p = 0; i < (int32_t)buf_size && p < max_hex_string; i += 1, p += 2)
        snprintf(hex_string + p, max_hex_string - p, "%02x", buf[i]);
    if (p < max_hex_string)
        hex_string[p] = 0;
}

TEST(crypt, rand) {
    uint8_t random_bytes[256];

    memset(random_bytes, 0, sizeof(random_bytes));

    EXPECT_EQ(mz_crypt_rand(random_bytes, sizeof(random_bytes)), sizeof(random_bytes));

    EXPECT_NE(std::string((char *)random_bytes, sizeof(random_bytes)).find_first_not_of('\0'), std::string::npos);
}

TEST(crypt, sha1) {
    void *sha1 = nullptr;
    uint8_t hash1[MZ_HASH_SHA1_SIZE];
    char computed_hash[256];

    memset(hash1, 0, sizeof(hash1));

    sha1 = mz_crypt_sha_create();
    ASSERT_NE(sha1, nullptr);
    mz_crypt_sha_set_algorithm(sha1, MZ_HASH_SHA1);
    mz_crypt_sha_begin(sha1);
    mz_crypt_sha_update(sha1, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha1, hash1, sizeof(hash1));
    mz_crypt_sha_delete(&sha1);

    convert_buffer_to_hex_string(hash1, sizeof(hash1), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "3efb8392b6cd8e14bd76bd08081521dc73df418c");
}

TEST(crypt, sha224) {
#  if GTEST_OS_WINDOWS
    GTEST_SKIP() << "SHA224 not supported on Windows";
#  else
    void *sha224 = nullptr;
    uint8_t hash224[MZ_HASH_SHA224_SIZE];
    char computed_hash[256];

    memset(hash224, 0, sizeof(hash224));

    sha224 = mz_crypt_sha_create();
    ASSERT_NE(sha224, nullptr);
    mz_crypt_sha_set_algorithm(sha224, MZ_HASH_SHA224);
    mz_crypt_sha_begin(sha224);
    mz_crypt_sha_update(sha224, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha224, hash224, sizeof(hash224));
    mz_crypt_sha_delete(&sha224);

    convert_buffer_to_hex_string(hash224, sizeof(hash224), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "9e444f5f0b6582a923bd48696155f4a2f0d914e044cb64b8729a6600");
#  endif
}

TEST(crypt, sha256) {
#  if GTEST_OS_WINDOWS && _WIN32_WINNT <= _WIN32_WINNT_XP
    GTEST_SKIP() << "SHA256 not supported on Windows XP";
#  else
    void *sha256 = nullptr;
    uint8_t hash256[MZ_HASH_SHA256_SIZE];
    char computed_hash[256];

    memset(hash256, 0, sizeof(hash256));

    sha256 = mz_crypt_sha_create();
    ASSERT_NE(sha256, nullptr);
    mz_crypt_sha_set_algorithm(sha256, MZ_HASH_SHA256);
    mz_crypt_sha_begin(sha256);
    mz_crypt_sha_update(sha256, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha256, hash256, sizeof(hash256));
    mz_crypt_sha_delete(&sha256);

    convert_buffer_to_hex_string(hash256, sizeof(hash256), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "7a31ea0848525f7ebfeec9ee532bcc5d6d26772427e097b86cf440a56546541c");
#  endif
}

TEST(crypt, sha384) {
#  if GTEST_OS_WINDOWS && _WIN32_WINNT <= _WIN32_WINNT_XP
    GTEST_SKIP() << "SHA384 not supported on Windows XP";
#  else
    void *sha384 = nullptr;
    uint8_t hash384[MZ_HASH_SHA384_SIZE];
    char computed_hash[256];

    memset(hash384, 0, sizeof(hash384));

    sha384 = mz_crypt_sha_create();
    ASSERT_NE(sha384, nullptr);
    mz_crypt_sha_set_algorithm(sha384, MZ_HASH_SHA384);
    mz_crypt_sha_begin(sha384);
    mz_crypt_sha_update(sha384, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha384, hash384, sizeof(hash384));
    mz_crypt_sha_delete(&sha384);

    convert_buffer_to_hex_string(hash384, sizeof(hash384), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash,
                 "e1e42e5977965bb3621231a5df3a1e83c471fa91fde33b6a30c8c4fa0d8be29ba7171c7c9487db91e9ee7e85049f7b41");
#  endif
}

TEST(crypt, sha512) {
#  if GTEST_OS_WINDOWS && _WIN32_WINNT <= _WIN32_WINNT_XP
    GTEST_SKIP() << "SHA512 not supported on Windows XP";
#  else
    void *sha512 = nullptr;
    uint8_t hash512[MZ_HASH_SHA512_SIZE];
    char computed_hash[256];

    memset(hash512, 0, sizeof(hash512));

    sha512 = mz_crypt_sha_create();
    ASSERT_NE(sha512, nullptr);
    mz_crypt_sha_set_algorithm(sha512, MZ_HASH_SHA512);
    mz_crypt_sha_begin(sha512);
    mz_crypt_sha_update(sha512, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha512, hash512, sizeof(hash512));
    mz_crypt_sha_delete(&sha512);

    convert_buffer_to_hex_string(hash512, sizeof(hash512), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash,
                 "6627e7643ee7ce633e03f52d22329c3a32597364247c5275d4369985e1518626da46f595ad327667346479d246359b8b381af"
                 "791ce2ac8c53a4788050eea11fe");
#  endif
}

TEST(crypt, aes128) {
    void *aes = nullptr;
    const char *key = "awesomekeythisis";
    const char *test = "youknowitsogrowi";
    const uint8_t cipher[] = {
        0x53, 0x45, 0xa5, 0xdc, 0xc4, 0x02, 0x96, 0xcb, 0xbb, 0x4a, 0xde, 0x25, 0x62, 0xd3, 0x80, 0x38,
    };
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_encrypt_key(aes, key, key_length, nullptr, 0);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_THAT(cipher, ::testing::ElementsAreArray(buf, test_length));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_decrypt_key(aes, key, key_length, nullptr, 0);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, aes128_cbc) {
    void *aes = nullptr;
    const char *key = "awesomekeythisis";
    const char *test = "youknowitsogrowi";
    const char *iv = "0123456789123456";
    const uint8_t cipher[] = {
        0x59, 0x44, 0xbd, 0xf8, 0x54, 0x8c, 0xf9, 0x0a, 0xfa, 0x34, 0x1e, 0xab, 0x42, 0x3d, 0xe1, 0x70,
    };
    int32_t key_length = 0;
    int32_t test_length = 0;
    int32_t iv_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);
    iv_length = (int32_t)strlen(iv);

    strncpy((char *)buf, test, sizeof(buf));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_mode(aes, MZ_AES_MODE_CBC);
    EXPECT_EQ(mz_crypt_aes_set_encrypt_key(aes, key, key_length, iv, iv_length), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_THAT(cipher, ::testing::ElementsAreArray(buf, test_length));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_mode(aes, MZ_AES_MODE_CBC);
    EXPECT_EQ(mz_crypt_aes_set_decrypt_key(aes, key, key_length, iv, iv_length), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, aes128_gcm) {
#  if GTEST_OS_WINDOWS && _WIN32_WINNT <= _WIN32_WINNT_XP
    GTEST_SKIP() << "SHA256 not supported on Windows XP";
#  else
    void *aes = nullptr;
    const char *key = "awesomekeythisis";
    const char *test = "youknowitsogrowi";
    const char *iv = "0123456789123456";
    const char *aad = "additional authentication data";

#    if GTEST_OS_WINDOWS
    // BCryptEncrypt hard-restricts the IV length to exactly 96 bits for AES-GCM.
    // The actual IV is "012345678912".
    const uint8_t cipher[] = {
        0xe1, 0xf1, 0x6a, 0xfc, 0xa8, 0x19, 0xba, 0x64, 0x8b, 0xd5, 0xb4, 0xf5, 0x9a, 0xce, 0xd0, 0x60,
    };
    const uint8_t tag[] = {
        0x9a, 0xa9, 0xc2, 0x30, 0xa5, 0x2f, 0x9c, 0xb6, 0x61, 0xf1, 0x67, 0xcb, 0xf5, 0x6d, 0x97, 0x31,
    };
#    else
    const uint8_t cipher[] = {
        0x89, 0x2e, 0xfc, 0x80, 0x7e, 0x5b, 0xb1, 0x62, 0x29, 0xb1, 0x1e, 0x5d, 0x37, 0x51, 0x43, 0x34,
    };
    const uint8_t tag[] = {
        0x52, 0x82, 0x9d, 0x91, 0x56, 0x76, 0xc8, 0x8e, 0x1d, 0xd0, 0x89, 0xb6, 0x8e, 0x45, 0x56, 0x27,
    };
#    endif
    int32_t key_length = 0;
    int32_t test_length = 0;
    int32_t iv_length = 0;
    int32_t aad_length = 0;
    uint8_t buf[120] = {0};
    uint8_t computed_tag[MZ_AES_BLOCK_SIZE] = {0};

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);
    iv_length = (int32_t)strlen(iv);
    aad_length = (int32_t)strlen(aad);

    strncpy((char *)buf, test, sizeof(buf));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_mode(aes, MZ_AES_MODE_GCM);
    EXPECT_EQ(mz_crypt_aes_set_encrypt_key(aes, key, key_length, iv, iv_length), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, aad, aad_length, buf, test_length), test_length);
    EXPECT_EQ(mz_crypt_aes_encrypt_final(aes, nullptr, 0, computed_tag, sizeof(computed_tag)), 0);
    mz_crypt_aes_delete(&aes);

    EXPECT_THAT(cipher, ::testing::ElementsAreArray(buf, test_length));
    EXPECT_THAT(computed_tag, ::testing::ElementsAreArray(tag));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_mode(aes, MZ_AES_MODE_GCM);
    EXPECT_EQ(mz_crypt_aes_set_decrypt_key(aes, key, key_length, iv, iv_length), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, aad, aad_length, buf, test_length), test_length);
    EXPECT_EQ(mz_crypt_aes_decrypt_final(aes, nullptr, 0, tag, sizeof(tag)), 0);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
#  endif
}

TEST(crypt, aes192) {
    void *aes = nullptr;
    const char *key = "awesomekeythisisbeefyone";
    const char *test = "youknowitsogrowi";
    const uint8_t cipher[] = {
        0x44, 0x49, 0x9e, 0x1b, 0x87, 0x97, 0xa1, 0xd1, 0x5d, 0x89, 0xd9, 0x71, 0xd0, 0xca, 0x08, 0xbc,
    };
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    EXPECT_EQ(mz_crypt_aes_set_encrypt_key(aes, key, key_length, nullptr, 0), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_THAT(cipher, ::testing::ElementsAreArray(buf, test_length));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    EXPECT_EQ(mz_crypt_aes_set_decrypt_key(aes, key, key_length, nullptr, 0), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, aes256) {
    void *aes = nullptr;
    const char *key = "awesomekeythisisevenmoresolidone";
    const char *test = "youknowitsogrowi";
    const uint8_t cipher[] = {
        0x1a, 0xf0, 0xe4, 0xf3, 0xdf, 0xe3, 0xc2, 0x64, 0x9d, 0x23, 0x52, 0x68, 0x0f, 0x10, 0xc2, 0x7e,
    };
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    EXPECT_EQ(mz_crypt_aes_set_encrypt_key(aes, key, key_length, nullptr, 0), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_THAT(cipher, ::testing::ElementsAreArray(buf, test_length));

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    EXPECT_EQ(mz_crypt_aes_set_decrypt_key(aes, key, key_length, nullptr, 0), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, nullptr, 0, buf, test_length), test_length);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

#  ifdef HAVE_WZAES
/* NIST SP 800-38A F.5.1 CTR-AES128.Encrypt */
static const uint8_t ctr_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t ctr_iv[] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
static const uint8_t ctr_plain[] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
};
static const uint8_t ctr_cipher[] = {
    0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff,
    0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab,
    0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee,
};

TEST(crypt, aes128_ctr) {
    void *ctr = nullptr;
    uint8_t buf[sizeof(ctr_plain)];

    memcpy(buf, ctr_plain, sizeof(buf));

    ctr = mz_crypt_aes_ctr_create();
    ASSERT_NE(ctr, nullptr);

    EXPECT_EQ(mz_crypt_aes_ctr_set_key(ctr, ctr_key, sizeof(ctr_key), ctr_iv, sizeof(ctr_iv)), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf, sizeof(buf)), MZ_OK);
    EXPECT_THAT(ctr_cipher, ::testing::ElementsAreArray(buf, sizeof(buf)));

    EXPECT_EQ(mz_crypt_aes_ctr_set_key(ctr, ctr_key, sizeof(ctr_key), ctr_iv, sizeof(ctr_iv)), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf, sizeof(buf)), MZ_OK);
    EXPECT_THAT(ctr_plain, ::testing::ElementsAreArray(buf, sizeof(buf)));

    mz_crypt_aes_ctr_delete(&ctr);
}

/* Keystream must not depend on how the caller splits its writes */
TEST(crypt, aes128_ctr_split) {
    void *ctr = nullptr;
    uint8_t buf[sizeof(ctr_plain)];
    int32_t chunks[] = {1, 7, 16, 17, 23};

    for (int32_t chunk : chunks) {
        memcpy(buf, ctr_plain, sizeof(buf));

        ctr = mz_crypt_aes_ctr_create();
        ASSERT_NE(ctr, nullptr);
        EXPECT_EQ(mz_crypt_aes_ctr_set_key(ctr, ctr_key, sizeof(ctr_key), ctr_iv, sizeof(ctr_iv)), MZ_OK);

        for (int32_t i = 0; i < (int32_t)sizeof(buf); i += chunk) {
            int32_t size = (int32_t)sizeof(buf) - i;
            if (size > chunk)
                size = chunk;

            EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf + i, size), MZ_OK);
        }

        mz_crypt_aes_ctr_delete(&ctr);

        EXPECT_THAT(ctr_cipher, ::testing::ElementsAreArray(buf, sizeof(buf))) << "chunk size " << chunk;
    }
}

/* Sizes that are not a multiple of the block size must not disturb the keystream */
TEST(crypt, aes128_ctr_partial_block) {
    int32_t sizes[] = {1, 5, 15, 17, 45, 63};

    for (int32_t size : sizes) {
        void *ctr = nullptr;
        uint8_t buf[sizeof(ctr_plain)];

        memcpy(buf, ctr_plain, sizeof(buf));

        ctr = mz_crypt_aes_ctr_create();
        ASSERT_NE(ctr, nullptr);
        EXPECT_EQ(mz_crypt_aes_ctr_set_key(ctr, ctr_key, sizeof(ctr_key), ctr_iv, sizeof(ctr_iv)), MZ_OK);

        /* Stop on a partial block, the unused keystream must carry to the next call */
        EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf, size), MZ_OK);
        EXPECT_EQ(memcmp(buf, ctr_cipher, size), 0) << "size " << size;

        EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf + size, (int32_t)sizeof(buf) - size), MZ_OK);
        EXPECT_THAT(ctr_cipher, ::testing::ElementsAreArray(buf, sizeof(buf))) << "size " << size;

        mz_crypt_aes_ctr_delete(&ctr);
    }
}

/* WinZip AES counts little endian across the low 8 bytes starting at one */
TEST(crypt, aes128_ctr_le8) {
    void *ctr = nullptr;
    const uint8_t nonce[MZ_AES_BLOCK_SIZE] = {1};
    uint8_t expected[MZ_AES_BLOCK_SIZE * 2];
    uint8_t buf[MZ_AES_BLOCK_SIZE * 2];
    void *aes = nullptr;

    /* Build the same keystream by hand out of the ECB primitive */
    memset(expected, 0, sizeof(expected));
    expected[0] = 1;
    expected[MZ_AES_BLOCK_SIZE] = 2;

    aes = mz_crypt_aes_create();
    ASSERT_NE(aes, nullptr);
    mz_crypt_aes_set_encrypt_key(aes, ctr_key, sizeof(ctr_key), nullptr, 0);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, nullptr, 0, expected, sizeof(expected)), (int32_t)sizeof(expected));
    mz_crypt_aes_delete(&aes);

    memset(buf, 0, sizeof(buf));

    ctr = mz_crypt_aes_ctr_create();
    ASSERT_NE(ctr, nullptr);
    mz_crypt_aes_ctr_set_counter(ctr, MZ_AES_CTR_LE8);
    EXPECT_EQ(mz_crypt_aes_ctr_set_key(ctr, ctr_key, sizeof(ctr_key), nonce, sizeof(nonce)), MZ_OK);
    EXPECT_EQ(mz_crypt_aes_ctr_encrypt(ctr, buf, sizeof(buf)), MZ_OK);
    mz_crypt_aes_ctr_delete(&ctr);

    EXPECT_THAT(expected, ::testing::ElementsAreArray(buf, sizeof(buf)));
}
#  endif

TEST(crypt, hmac_sha1) {
    void *hmac;
    const char *key = "hm123";
    const char *test = "12345678";
    char computed_hash[256];
    uint8_t hash1[MZ_HASH_SHA1_SIZE];

    hmac = mz_crypt_hmac_create();
    ASSERT_NE(hmac, nullptr);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA1);
    mz_crypt_hmac_init(hmac, key, (int32_t)strlen(key));
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_end(hmac, hash1, sizeof(hash1));
    mz_crypt_hmac_delete(&hmac);

    convert_buffer_to_hex_string(hash1, sizeof(hash1), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "3c8c576d947994177af9366c05a6d6cb060edab7");
}

TEST(crypt, hmac_sha1_short_password) {
    /* Test fixes for CryptImportKey returning ERROR_INVALID_PARAMETER on Windows */
    void *hmac;
    /* Intended key is "h", the extra "x" helps test that padding does not read past supplied length */
    const char *key = "hx";
    const char *test = "helloworld";
    char computed_hash[256];
    uint8_t hash1[MZ_HASH_SHA1_SIZE];

    hmac = mz_crypt_hmac_create();
    ASSERT_NE(hmac, nullptr);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA1);
    /* Key length is 1, only first char from key should used for this test */
    mz_crypt_hmac_init(hmac, key, 1);
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_end(hmac, hash1, sizeof(hash1));
    mz_crypt_hmac_delete(&hmac);

    convert_buffer_to_hex_string(hash1, sizeof(hash1), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "0d216a670164deca30181479908f65b6b01199e2");
}

TEST(crypt, hmac_sha256) {
#  if GTEST_OS_WINDOWS && _WIN32_WINNT <= _WIN32_WINNT_XP
    GTEST_SKIP() << "SHA256 not supported on Windows XP";
#  else
    void *hmac;
    const char *key = "hm123";
    const char *test = "12345678";
    char computed_hash[256];
    uint8_t hash256[MZ_HASH_SHA256_SIZE];

    hmac = mz_crypt_hmac_create();
    ASSERT_NE(hmac, nullptr);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA256);
    mz_crypt_hmac_init(hmac, key, (int32_t)strlen(key));
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_end(hmac, hash256, sizeof(hash256));
    mz_crypt_hmac_delete(&hmac);

    convert_buffer_to_hex_string(hash256, sizeof(hash256), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "fb22a9c715a47a06bad4f6cee9badc31c921562f5d6b24adf2be009f73181f7a");
#  endif
}

#  ifdef HAVE_WZAES
TEST(crypt, pbkdf2) {
    uint16_t iteration_count = 1000;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "passwordpasswordpasswordpassword";
    const char *salt = "8F3472E4EA57F56E36F30246DC22C173";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "852c7b71a104aaa8d8996c840c3d4d5d0db780aa");
}

TEST(crypt, pbkdf2_long_odd_password) {
    uint16_t iteration_count = 1000;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    /* Password has odd length and longer than 64 chars */
    const char *password = "passwordpasswordpasswordpasswordpasswordpasswordpasswordpasswordp";
    const char *salt = "8F3472E4EA57F56E36F30246DC22C173";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "b3e0b5ece77332506972e97b63b3a0a6d36c39a9");
}

TEST(crypt, pbkdf2_short_password) {
    /* Test fixes for CryptImportKey returns ERROR_INVALID_PARAMETER on Windows */
    uint16_t iteration_count = 1000;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "p";
    const char *salt = "8F3472E4EA57F56E36F30246DC22C173";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "91cf25bb4c2978620255d7fed8cc1751c7d283b9");
}

TEST(crypt, pbkdf2_rfc6070_v1) {
    /* https://www.ietf.org/rfc/rfc6070.txt */
    uint16_t iteration_count = 2;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "password";
    const char *salt = "salt";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
}

TEST(crypt, pbkdf2_rfc6070_v2) {
    /* https://www.ietf.org/rfc/rfc6070.txt */
    uint16_t iteration_count = 4096;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "password";
    const char *salt = "salt";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "4b007901b765489abead49d926f721d065a429c1");
}

TEST(crypt, pbkdf2_rfc6070_v3) {
    /* https://www.ietf.org/rfc/rfc6070.txt */
    uint32_t iteration_count = 16777216U;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "password";
    const char *salt = "salt";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
}

TEST(crypt, pbkdf2_rfc6070_v4) {
    /* https://www.ietf.org/rfc/rfc6070.txt */
    uint16_t iteration_count = 4096;
    uint8_t key[25];
    char key_hex[256];
    const char *password = "passwordPASSWORDpassword";
    const char *salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password), (uint8_t *)salt, (int32_t)strlen(salt),
                              iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
}

TEST(crypt, pbkdf2_rfc6070_v5) {
    /* https://www.ietf.org/rfc/rfc6070.txt */
    uint16_t iteration_count = 4096;
    uint8_t key[16];
    char key_hex[256];
    const char *password = "pass\0word";
    const char *salt = "sa\0lt";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, 9, (uint8_t *)salt, 5, iteration_count, key, (uint16_t)sizeof(key)),
              MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "56fa6aa75548099dcc37d7f03425e0c3");
}
#  endif
#endif
