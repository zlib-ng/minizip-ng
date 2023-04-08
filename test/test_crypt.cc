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

#include <stdio.h> /* printf, snprintf */

#ifndef MZ_ZIP_NO_CRYPTO
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

    EXPECT_NE(std::string((char *)random_bytes).find_first_not_of('\0'), std::string::npos);
}

TEST(crypt, sha1) {
    void *sha1 = NULL;
    uint8_t hash1[MZ_HASH_SHA1_SIZE];
    char computed_hash[256];

    memset(hash1, 0, sizeof(hash1));

    mz_crypt_sha_create(&sha1);
    mz_crypt_sha_set_algorithm(sha1, MZ_HASH_SHA1);
    mz_crypt_sha_begin(sha1);
    mz_crypt_sha_update(sha1, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha1, hash1, sizeof(hash1));
    mz_crypt_sha_delete(&sha1);

    convert_buffer_to_hex_string(hash1, sizeof(hash1), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "3efb8392b6cd8e14bd76bd08081521dc73df418c");
}

TEST(crypt, sha224) {
    void *sha224 = NULL;
    uint8_t hash224[MZ_HASH_SHA224_SIZE];
    char computed_hash[256];

    memset(hash224, 0, sizeof(hash224));

    mz_crypt_sha_create(&sha224);
    mz_crypt_sha_set_algorithm(sha224, MZ_HASH_SHA224);
    mz_crypt_sha_begin(sha224);
    mz_crypt_sha_update(sha224, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha224, hash224, sizeof(hash224));
    mz_crypt_sha_delete(&sha224);

    convert_buffer_to_hex_string(hash224, sizeof(hash224), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "9e444f5f0b6582a923bd48696155f4a2f0d914e044cb64b8729a6600");
}

TEST(crypt, sha256) {
    void *sha256 = NULL;
    uint8_t hash256[MZ_HASH_SHA256_SIZE];
    char computed_hash[256];

    memset(hash256, 0, sizeof(hash256));

    mz_crypt_sha_create(&sha256);
    mz_crypt_sha_set_algorithm(sha256, MZ_HASH_SHA256);
    mz_crypt_sha_begin(sha256);
    mz_crypt_sha_update(sha256, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha256, hash256, sizeof(hash256));
    mz_crypt_sha_delete(&sha256);

    convert_buffer_to_hex_string(hash256, sizeof(hash256), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "7a31ea0848525f7ebfeec9ee532bcc5d6d26772427e097b86cf440a56546541c");
}

TEST(crypt, sha384) {
    void *sha384 = NULL;
    uint8_t hash384[MZ_HASH_SHA384_SIZE];
    char computed_hash[256];

    memset(hash384, 0, sizeof(hash384));

    mz_crypt_sha_create(&sha384);
    mz_crypt_sha_set_algorithm(sha384, MZ_HASH_SHA384);
    mz_crypt_sha_begin(sha384);
    mz_crypt_sha_update(sha384, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha384, hash384, sizeof(hash384));
    mz_crypt_sha_delete(&sha384);

    convert_buffer_to_hex_string(hash384, sizeof(hash384), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "e1e42e5977965bb3621231a5df3a1e83c471fa91fde33b6a30c8c4fa0d8be29ba7171c7c9487db91e9ee7e85049f7b41");
}

TEST(crypt, sha512) {
    void *sha512 = NULL;
    uint8_t hash512[MZ_HASH_SHA512_SIZE];
    char computed_hash[256];

    memset(hash512, 0, sizeof(hash512));

    mz_crypt_sha_create(&sha512);
    mz_crypt_sha_set_algorithm(sha512, MZ_HASH_SHA512);
    mz_crypt_sha_begin(sha512);
    mz_crypt_sha_update(sha512, hash_test_string, (int32_t)strlen(hash_test_string));
    mz_crypt_sha_end(sha512, hash512, sizeof(hash512));
    mz_crypt_sha_delete(&sha512);

    convert_buffer_to_hex_string(hash512, sizeof(hash512), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "6627e7643ee7ce633e03f52d22329c3a32597364247c5275d4369985e1518626da46f595ad327667346479d246359b8b381af791ce2ac8c53a4788050eea11fe");
}

TEST(crypt, aes128) {
    void *aes = NULL;
    const char *key = "awesomekeythisis";
    const char *test = "youknowitsogrowi";
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_encrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STRNE((char *)buf, test);

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_decrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, aes194) {
    void *aes = NULL;
    const char *key = "awesomekeythisisbeefyone";
    const char *test = "youknowitsogrowi";
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_encrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STRNE((char *)buf, test);

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_decrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, aes256) {
    void *aes = NULL;
    const char *key = "awesomekeythisisevenmoresolidone";
    const char *test = "youknowitsogrowi";
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];

    key_length = (int32_t)strlen(key);
    test_length = (int32_t)strlen(test);

    strncpy((char *)buf, test, sizeof(buf));

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_encrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_encrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STRNE((char *)buf, test);

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_decrypt_key(aes, key, key_length);
    EXPECT_EQ(mz_crypt_aes_decrypt(aes, buf, test_length), 16);
    mz_crypt_aes_delete(&aes);

    EXPECT_STREQ((char *)buf, test);
}

TEST(crypt, hmac_sha1) {
    void *hmac;
    const char *key = "hm123";
    const char *test = "12345678";
    char computed_hash[256];
    uint8_t hash1[MZ_HASH_SHA1_SIZE];

    mz_crypt_hmac_create(&hmac);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA1);
    mz_crypt_hmac_init(hmac, key, (int32_t)strlen(key));
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_end(hmac, hash1, sizeof(hash1));
    mz_crypt_hmac_delete(&hmac);

    convert_buffer_to_hex_string(hash1, sizeof(hash1), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "c785a02ff303c886c304d9a4c06073dfe4c24aa9");
}

TEST(crypt, hmac_sha1_short_password) {
    /* Test fixes for CryptImportKey returning ERROR_INVALID_PARAMETER on Windows */
    void *hmac;
    /* Intended key is "h", the extra "x" helps test that padding does not read past supplied length */
    const char *key = "hx";
    const char *test = "helloworld";
    char computed_hash[256];
    uint8_t hash1[MZ_HASH_SHA1_SIZE];

    mz_crypt_hmac_create(&hmac);
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
    void *hmac;
    const char *key = "hm123";
    const char *test = "12345678";
    char computed_hash[256];
    uint8_t hash256[MZ_HASH_SHA256_SIZE];

    mz_crypt_hmac_create(&hmac);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA256);
    mz_crypt_hmac_init(hmac, key, (int32_t)strlen(key));
    mz_crypt_hmac_update(hmac, test, (int32_t)strlen(test));
    mz_crypt_hmac_end(hmac, hash256, sizeof(hash256));
    mz_crypt_hmac_delete(&hmac);

    convert_buffer_to_hex_string(hash256, sizeof(hash256), computed_hash, sizeof(computed_hash));

    EXPECT_STREQ(computed_hash, "fb22a9c715a47a06bad4f6cee9badc31c921562f5d6b24adf2be009f73181f7a");
}

#ifdef HAVE_WZAES
TEST(crypt, pbkdf2) {
    uint16_t iteration_count = 1000;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    char key_hex[256];
    const char *password = "passwordpasswordpasswordpassword";
    const char *salt = "8F3472E4EA57F56E36F30246DC22C173";

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, (int32_t)strlen(password),
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

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

    EXPECT_EQ(mz_crypt_pbkdf2((uint8_t *)password, 9,
        (uint8_t *)salt, 5, iteration_count, key, (uint16_t)sizeof(key)), MZ_OK);

    convert_buffer_to_hex_string(key, sizeof(key), key_hex, sizeof(key_hex));

    EXPECT_STREQ(key_hex, "56fa6aa75548099dcc37d7f03425e0c3");
}
#endif
#endif
