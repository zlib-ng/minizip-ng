#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "mz.h"
#include "mz_crypt.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_crc32.h"
#ifdef HAVE_BZIP
#include "mz_strm_bzip.h"
#endif
#ifdef HAVE_PKCRYPT
#include "mz_strm_pkcrypt.h"
#endif
#include "mz_strm_mem.h"
#include "mz_strm_os.h"
#ifdef HAVE_AES
#include "mz_strm_wzaes.h"
#endif
#ifdef HAVE_ZLIB
#include "mz_strm_zlib.h"
#endif
#include "mz_zip.h"

/***************************************************************************/

void test_path_resolve(void)
{
    char output[256];
    int32_t ok = 0;

    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\.", output, sizeof(output));
    ok = (strcmp(output, "c:\\test\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\.\\", output, sizeof(output));
    ok = (strcmp(output, "c:\\test\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\..", output, sizeof(output));
    ok = (strcmp(output, "c:\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\..\\", output, sizeof(output));
    ok = (strcmp(output, "c:\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\.\\..", output, sizeof(output));
    ok = (strcmp(output, "c:\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\.\\\\..", output, sizeof(output));
    ok = (strcmp(output, "c:\\") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve(".", output, sizeof(output));
    ok = (strcmp(output, ".") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve(".\\", output, sizeof(output));
    ok = (strcmp(output, "") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("..", output, sizeof(output));
    ok = (strcmp(output, "") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("..\\", output, sizeof(output));
    ok = (strcmp(output, "") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\123\\.\\abc.txt", output, sizeof(output));
    ok = (strcmp(output, "c:\\test\\123\\abc.txt") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\123\\..\\abc.txt", output, sizeof(output));
    ok = (strcmp(output, "c:\\test\\abc.txt") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\123\\..\\..\\abc.txt", output, sizeof(output));
    ok = (strcmp(output, "c:\\abc.txt") == 0);
    memset(output, 'z', sizeof(output));
    mz_path_resolve("c:\\test\\123\\..\\..\\..\\abc.txt", output, sizeof(output));
    ok = (strcmp(output, "abc.txt") == 0);
    memset(output, 'z', sizeof(output));
    printf("ok = %d", ok);
}

void test_encrypt(char *method, mz_stream_create_cb crypt_create, char *password)
{
    char buf[UINT16_MAX];
    int16_t read = 0;
    int16_t written = 0;
    void *out_stream = NULL;
    void *in_stream = NULL;
    void *crypt_out_stream = NULL;
    char encrypt_path[120];
    char decrypt_path[120];
    
    snprintf(encrypt_path, sizeof(encrypt_path), "LICENSE.encrypt.%s", method);
    snprintf(decrypt_path, sizeof(decrypt_path), "LICENSE.decrypt.%s", method);

    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, "LICENSE", MZ_OPEN_MODE_READ) == MZ_OK)
    {
        read = mz_stream_os_read(in_stream, buf, UINT16_MAX);
        mz_stream_os_close(in_stream);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);

    if (mz_stream_os_open(out_stream, encrypt_path, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE) == MZ_OK)
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, out_stream);

        if (mz_stream_open(crypt_out_stream, password, MZ_OPEN_MODE_WRITE) == MZ_OK)
        {
            written = mz_stream_write(crypt_out_stream, buf, read);
            mz_stream_close(crypt_out_stream);
        }

        mz_stream_delete(&crypt_out_stream);

        mz_stream_os_close(out_stream);

        printf("%s encrypted %d\n", encrypt_path, written);
    }
    
    mz_stream_os_delete(&out_stream);
    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, encrypt_path, MZ_OPEN_MODE_READ) == MZ_OK)
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, in_stream);

        if (mz_stream_open(crypt_out_stream, password, MZ_OPEN_MODE_READ) == MZ_OK)
        {
            read = mz_stream_read(crypt_out_stream, buf, read);
            mz_stream_close(crypt_out_stream);
        }
        
        mz_stream_delete(&crypt_out_stream);

        mz_stream_os_close(in_stream);


        printf("%s decrypted %d\n", decrypt_path, read);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);
    
    if (mz_stream_os_open(out_stream, decrypt_path, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE) == MZ_OK)
    {
        mz_stream_os_write(out_stream, buf, read);
        mz_stream_os_close(out_stream);
    }

    mz_stream_os_delete(&out_stream);
}

void test_compress(char *method, mz_stream_create_cb create_compress)
{
    char buf[UINT16_MAX];
    int16_t read = 0;
    int64_t total_in = 0;
    int64_t total_out = 0;
    void *crc_in_stream = NULL;
    void *in_stream = NULL;
    void *out_stream = NULL;
    void *deflate_stream = NULL;
    void *inflate_stream = NULL;
    uint32_t crc32 = 0;
    char filename[120];

    printf("Testing compress %s\n", method);

    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, "LICENSE", MZ_OPEN_MODE_READ) == MZ_OK)
    {
        mz_stream_crc32_create(&crc_in_stream);
        mz_stream_set_base(crc_in_stream, in_stream);
        mz_stream_crc32_open(crc_in_stream, NULL, MZ_OPEN_MODE_READ);
        read = mz_stream_read(crc_in_stream, buf, UINT16_MAX);
        crc32 = mz_stream_crc32_get_value(crc_in_stream);
        mz_stream_close(crc_in_stream);
        mz_stream_crc32_delete(&crc_in_stream);

        mz_stream_os_close(in_stream);
    }

    mz_stream_os_delete(&in_stream);

    if (read < 0)
    {
        printf("Failed to read LICENSE\n");
        return;
    }

    printf("LICENSE crc 0x%08x\n", crc32);

    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.deflate.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE) == MZ_OK)
    {
        create_compress(&deflate_stream);
        mz_stream_set_base(deflate_stream, out_stream);

        mz_stream_open(deflate_stream, NULL, MZ_OPEN_MODE_WRITE);
        mz_stream_write(deflate_stream, buf, read);
        mz_stream_close(deflate_stream);

        mz_stream_get_prop_int64(deflate_stream, MZ_STREAM_PROP_TOTAL_IN, &total_in);
        mz_stream_get_prop_int64(deflate_stream, MZ_STREAM_PROP_TOTAL_OUT, &total_out);

        mz_stream_delete(&deflate_stream);

        printf("%s compressed from %u to %u\n", filename, (uint32_t)total_in, (uint32_t)total_out);

        mz_stream_os_close(out_stream);
    }
    
    mz_stream_os_delete(&out_stream);
    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, filename, MZ_OPEN_MODE_READ) == MZ_OK)
    {
        create_compress(&inflate_stream);
        mz_stream_set_base(inflate_stream, in_stream);

        mz_stream_open(inflate_stream, NULL, MZ_OPEN_MODE_READ);
        read = mz_stream_read(inflate_stream, buf, UINT16_MAX);
        mz_stream_close(inflate_stream);

        mz_stream_get_prop_int64(inflate_stream, MZ_STREAM_PROP_TOTAL_IN, &total_in);
        mz_stream_get_prop_int64(inflate_stream, MZ_STREAM_PROP_TOTAL_OUT, &total_out);

        mz_stream_delete(&inflate_stream);

        mz_stream_os_close(in_stream);

        printf("%s uncompressed from %u to %u\n", filename, (uint32_t)total_in, (uint32_t)total_out);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.inflate.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE) == MZ_OK)
    {
        mz_stream_crc32_create(&crc_in_stream);
        mz_stream_crc32_open(crc_in_stream, NULL, MZ_OPEN_MODE_WRITE);

        mz_stream_set_base(crc_in_stream, in_stream);
        if (mz_stream_write(crc_in_stream, buf, read) != read)
            printf("Failed to write %s\n", filename);

        crc32 = mz_stream_crc32_get_value(crc_in_stream);

        mz_stream_close(crc_in_stream);
        mz_stream_delete(&crc_in_stream);

        mz_stream_os_close(out_stream);

        printf("%s crc 0x%08x\n", filename, crc32);
    }
    
    mz_stream_os_delete(&out_stream);
}

/***************************************************************************/

#ifdef HAVE_BZIP
void test_stream_bzip(void)
{
    test_compress("bzip", mz_stream_bzip_create);
}
#endif
#ifdef HAVE_PKCRYPT
void test_stream_pkcrypt(void)
{
    test_encrypt("pkcrypt", mz_stream_pkcrypt_create, "hello");
}
#endif
#ifdef HAVE_AES
void test_stream_wzaes(void)
{
    int32_t iteration_count = 1000;
    int32_t err = MZ_OK;
    int32_t i = 0;
    uint8_t key[MZ_HASH_SHA1_SIZE];
    const char *password = "passwordpasswordpasswordpassword";
    const char *salt = "8F3472E4EA57F56E36F30246DC22C173";
   

    printf("Pbkdf2 password - %s\n", password);
    printf("Pbkdf2 salt - %s\n", salt);

    err = mz_stream_wzaes_pbkdf2((uint8_t *)password, (int32_t)strlen(password), 
        (uint8_t *)salt, (int32_t)strlen(salt), iteration_count, key, sizeof(key));

    if (err == MZ_OK)
    {
        printf("Pbkdf2 key hex\n");
        for (i = 0; i < (int32_t)sizeof(key); i += 1)
            printf("%02x", key[i]);
        printf("\n");
    }
    else
    {
        printf("Pbkdf2 failed - %d", err);
    }

    test_encrypt("aes", mz_stream_wzaes_create, "hello");
}
#endif
#ifdef HAVE_ZLIB
void test_stream_zlib(void)
{
    test_compress("zlib", mz_stream_zlib_create);
}
#endif

/***************************************************************************/

void test_stream_mem(void)
{
    mz_zip_file file_info = { 0 };
    void *read_mem_stream = NULL;
    void *write_mem_stream = NULL;
    void *os_stream = NULL;
    void *zip_handle = NULL;
    int32_t written = 0;
    int32_t read = 0;
    int32_t text_size = 0;
    int32_t buffer_size = 0;
    int32_t err = MZ_OK;
    const uint8_t *buffer_ptr = NULL;
    char *password = "1234";
    char *text_name = "test";
    char *text_ptr = "test string";
    char temp[120];


    text_size = (int32_t)strlen(text_ptr);

    // Write zip to memory stream
    mz_stream_mem_create(&write_mem_stream);
    mz_stream_mem_set_grow_size(write_mem_stream, 128 * 1024);
    mz_stream_open(write_mem_stream, NULL, MZ_OPEN_MODE_CREATE);

    mz_zip_create(&zip_handle);
    err = mz_zip_open(zip_handle, write_mem_stream, MZ_OPEN_MODE_READWRITE);

    if (err == MZ_OK)
    {
        file_info.version_madeby = MZ_VERSION_MADEBY;
        file_info.compression_method = MZ_COMPRESS_METHOD_DEFLATE;
        file_info.filename = text_name;
        file_info.uncompressed_size = text_size;
#ifdef HAVE_AES
        file_info.aes_version = MZ_AES_VERSION;
#endif

        err = mz_zip_entry_write_open(zip_handle, &file_info, MZ_COMPRESS_LEVEL_DEFAULT, 0, password);
        if (err == MZ_OK)
        {
            written = mz_zip_entry_write(zip_handle, text_ptr, text_size);
            if (written < MZ_OK)
                err = written;
            mz_zip_entry_close(zip_handle);
        }

        mz_zip_close(zip_handle);
    }
    else
    {
        err = MZ_INTERNAL_ERROR;
    }

    mz_zip_delete(&zip_handle);

    mz_stream_mem_get_buffer(write_mem_stream, (const void **)&buffer_ptr);
    mz_stream_mem_seek(write_mem_stream, 0, MZ_SEEK_END);
    buffer_size = (int32_t)mz_stream_mem_tell(write_mem_stream);

    if (err == MZ_OK)
    {
        // Create a zip file on disk for inspection
        mz_stream_os_create(&os_stream);
        mz_stream_os_open(os_stream, "mytest.zip", MZ_OPEN_MODE_WRITE | MZ_OPEN_MODE_CREATE);
        mz_stream_os_write(os_stream, buffer_ptr, buffer_size);
        mz_stream_os_close(os_stream);
        mz_stream_os_delete(&os_stream);
    }

    if (err == MZ_OK)
    {
        // Read from a memory stream
        mz_stream_mem_create(&read_mem_stream);
        mz_stream_mem_set_buffer(read_mem_stream, (void *)buffer_ptr, buffer_size);
        mz_stream_open(read_mem_stream, NULL, MZ_OPEN_MODE_READ);

        mz_zip_create(&zip_handle);
        err = mz_zip_open(zip_handle, read_mem_stream, MZ_OPEN_MODE_READ);

        if (err == MZ_OK)
        {
            err = mz_zip_goto_first_entry(zip_handle);
            if (err == MZ_OK)
                err = mz_zip_entry_read_open(zip_handle, 0, password);
            if (err == MZ_OK)
                read = mz_zip_entry_read(zip_handle, temp, sizeof(temp));

            MZ_UNUSED(read);

            mz_zip_entry_close(zip_handle);
            mz_zip_close(zip_handle);
        }

        mz_zip_delete(&zip_handle);

        mz_stream_mem_close(&read_mem_stream);
        mz_stream_mem_delete(&read_mem_stream);
        read_mem_stream = NULL;
    }

    mz_stream_mem_close(write_mem_stream);
    mz_stream_mem_delete(&write_mem_stream);
    write_mem_stream = NULL;
}

/***************************************************************************/

#ifndef MZ_ZIP_NO_ENCRYPTION
void test_crypt_sha(void)
{
    void *sha1 = NULL;
    void *sha256 = NULL;
    char *test = "the quick and lazy fox did his thang";
    char computed_hash[320];
    int32_t i = 0;
    int32_t p = 0;
    uint8_t hash[MZ_HASH_SHA1_SIZE];
    uint8_t hash256[MZ_HASH_SHA256_SIZE];

    printf("Sha hash input - %s\n", test);

    memset(hash, 0, sizeof(hash));

    mz_crypt_sha_create(&sha1);
    mz_crypt_sha_set_algorithm(sha1, MZ_HASH_SHA1);
    mz_crypt_sha_begin(sha1);
    mz_crypt_sha_update(sha1, test, strlen(test));
    mz_crypt_sha_end(sha1, hash, sizeof(hash));
    mz_crypt_sha_delete(&sha1);

    computed_hash[0] = 0;
    for (i = 0, p = 0; i < (int32_t)sizeof(hash); i += 1, p += 2)
        snprintf(computed_hash + p, sizeof(computed_hash) - p, "%02x", hash[i]);
    computed_hash[p] = 0;
    
    printf("Sha1 hash computed - %s\n", computed_hash);
    printf("Sha1 hash expected - 3efb8392b6cd8e14bd76bd08081521dc73df418c\n");

    memset(hash256, 0, sizeof(hash256));

    mz_crypt_sha_create(&sha256);
    mz_crypt_sha_set_algorithm(sha256, MZ_HASH_SHA256);
    mz_crypt_sha_begin(sha256);
    mz_crypt_sha_update(sha256, test, strlen(test));
    mz_crypt_sha_end(sha256, hash256, sizeof(hash256));
    mz_crypt_sha_delete(&sha256);

    computed_hash[0] = 0;
    for (i = 0, p = 0; i < (int32_t)sizeof(hash256); i += 1, p += 2)
        snprintf(computed_hash + p, sizeof(computed_hash) - p, "%02x", hash256[i]);
    computed_hash[p] = 0;
    
    printf("Sha256 hash computed - %s\n", computed_hash);
    printf("Sha256 hash expected - 7a31ea0848525f7ebfeec9ee532bcc5d6d26772427e097b86cf440a56546541c\n");
}

void test_crypt_aes(void)
{
    void *aes = NULL;
    char *key = "awesomekeythisis";
    char *test = "youknowitsogrowi";
    int32_t key_length = 0;
    int32_t test_length = 0;
    uint8_t buf[120];
    int32_t i = 0;
    uint8_t hash[MZ_HASH_SHA256_SIZE];

    printf("Aes key - %s\n", key);
    printf("Aes input - %s\n", test);

    memset(hash, 0, sizeof(hash));

    key_length = strlen(key);
    test_length = strlen(test);

    strncpy((char *)buf, test, test_length);

    printf("Aes input hex\n");
    for (i = 0; i < test_length; i += 1)
        printf("%02x", buf[i]);
    printf("\n");

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_mode(aes, MZ_AES_ENCRYPTION_MODE_256);
    mz_crypt_aes_set_encrypt_key(aes, key, key_length);
    mz_crypt_aes_encrypt(aes, buf, test_length);
    mz_crypt_aes_delete(&aes);

    printf("Aes encrypted\n");
    for (i = 0; i < test_length; i += 1)
        printf("%02x", buf[i]);
    printf("\n");

    mz_crypt_aes_create(&aes);
    mz_crypt_aes_set_mode(aes, MZ_AES_ENCRYPTION_MODE_256);
    mz_crypt_aes_set_decrypt_key(aes, key, key_length);
    mz_crypt_aes_decrypt(aes, buf, test_length);
    mz_crypt_aes_delete(&aes);

    printf("Aes decrypted\n");
    for (i = 0; i < test_length; i += 1)
        printf("%02x", buf[i]);
    printf("\n");
}

void test_crypt_hmac(void)
{
    void *hmac;
    char *key = "hm123";
    char *test = "12345678";
    int32_t key_length = 0;
    int32_t test_length = 0;
    int32_t i = 0;
    uint8_t hash[MZ_HASH_SHA1_SIZE];
    uint8_t hash256[MZ_HASH_SHA256_SIZE];

    key_length = strlen(key);
    test_length = strlen(test);

    printf("Hmac sha1 key - %s\n", key);
    printf("Hmac sha1 input - %s\n", test);

    mz_crypt_hmac_create(&hmac);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA1);
    mz_crypt_hmac_init(hmac, key, key_length);
    mz_crypt_hmac_update(hmac, test, test_length);
    mz_crypt_hmac_end(hmac, hash, sizeof(hash));
    mz_crypt_hmac_delete(&hmac);

    printf("Hmac sha1 output hash hex\n");
    for (i = 0; i < (int32_t)sizeof(hash); i += 1)
        printf("%02x", hash[i]);
    printf("\n");
    printf("Hmac sha1 expected\n");
    printf("c785a02ff303c886c304d9a4c06073dfe4c24aa9\n");

    printf("Hmac sha256 key - %s\n", key);
    printf("Hmac sha256 input - %s\n", test);

    mz_crypt_hmac_create(&hmac);
    mz_crypt_hmac_set_algorithm(hmac, MZ_HASH_SHA256);
    mz_crypt_hmac_init(hmac, key, key_length);
    mz_crypt_hmac_update(hmac, test, test_length);
    mz_crypt_hmac_end(hmac, hash256, sizeof(hash256));
    mz_crypt_hmac_delete(&hmac);

    printf("Hmac sha256 output hash hex\n");
    for (i = 0; i < (int32_t)sizeof(hash256); i += 1)
        printf("%02x", hash256[i]);
    printf("\n");
    printf("Hmac sha256 expected\n");
    printf("fb22a9c715a47a06bad4f6cee9badc31c921562f5d6b24adf2be009f73181f7a\n");
}
#endif

/***************************************************************************/