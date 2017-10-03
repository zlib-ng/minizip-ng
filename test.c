#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "mzstrm.h"
#include "mzstrm_bzip.h"
#include "mzstrm_crypt.h"
#include "mzstrm_aes.h"
#include "mzstrm_zlib.h"

void test_encrypt(char *method, mz_stream_create_cb crypt_create, char *password)
{
    char buf[UINT16_MAX];
    int16_t read = 0;
    int16_t written = 0;
    void *out_stream = NULL;
    void *in_stream = NULL;
    void *crypt_out_stream = NULL;
    char filename[120];

    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, "LICENSE", MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        read = mz_stream_os_read(in_stream, buf, UINT16_MAX);
        mz_stream_os_close(in_stream);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.encrypt.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_STREAM_MODE_CREATE | MZ_STREAM_MODE_WRITE) == MZ_STREAM_OK)
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, out_stream);

        if (mz_stream_open(crypt_out_stream, password, MZ_STREAM_MODE_WRITE) == MZ_STREAM_OK)
        {
            written = mz_stream_write(crypt_out_stream, buf, read);
            mz_stream_close(crypt_out_stream);
        }

        mz_stream_delete(&crypt_out_stream);

        mz_stream_os_close(out_stream);

        printf("%s encrypted %d\n", filename, written);
    }
    
    mz_stream_os_delete(&out_stream);
    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, filename, MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, in_stream);

        if (mz_stream_open(crypt_out_stream, password, MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
        {
            read = mz_stream_read(crypt_out_stream, buf, read);
            mz_stream_close(crypt_out_stream);
        }
        
        mz_stream_delete(&crypt_out_stream);

        mz_stream_os_close(in_stream);

        printf("%s decrypted %d\n", filename, read);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.decrypt.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_STREAM_MODE_CREATE | MZ_STREAM_MODE_WRITE) == MZ_STREAM_OK)
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
    uint64_t total_in = 0;
    uint64_t total_out = 0;
    void *crc_in_stream = NULL;
    void *in_stream = NULL;
    void *out_stream = NULL;
    void *deflate_stream = NULL;
    void *inflate_stream = NULL;
    uint32_t crc32 = 0;
    char filename[120];

    printf("Testing compress %s\n", method);

    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, "LICENSE", MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        mz_stream_crc32_create(&crc_in_stream);
        mz_stream_set_base(crc_in_stream, in_stream);
        mz_stream_crc32_open(crc_in_stream, NULL, MZ_STREAM_MODE_READ);
        read = mz_stream_read(crc_in_stream, buf, UINT16_MAX);
        crc32 = mz_stream_crc32_get_value(crc_in_stream);
        mz_stream_close(crc_in_stream);
        mz_stream_crc32_delete(&crc_in_stream);

        mz_stream_os_close(in_stream);
    }

    mz_stream_os_delete(&in_stream);

    if (read == MZ_STREAM_ERR)
    {
        printf("Failed to read LICENSE\n");
        return;
    }

    printf("LICENSE crc 0x%08x\n", crc32);

    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.deflate.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_STREAM_MODE_CREATE | MZ_STREAM_MODE_WRITE) == MZ_STREAM_OK)
    {
        create_compress(&deflate_stream);
        mz_stream_set_base(deflate_stream, out_stream);

        mz_stream_open(deflate_stream, NULL, MZ_STREAM_MODE_WRITE);
        mz_stream_write(deflate_stream, buf, read);
        mz_stream_close(deflate_stream);

        total_in = mz_stream_get_total_in(deflate_stream);
        total_out = mz_stream_get_total_out(deflate_stream);

        mz_stream_delete(&deflate_stream);

        printf("%s compressed from %d to %d\n", filename, (uint32_t)total_in, (uint32_t)total_out);

        mz_stream_os_close(out_stream);
    }
    
    mz_stream_os_delete(&out_stream);
    mz_stream_os_create(&in_stream);

    if (mz_stream_os_open(in_stream, filename, MZ_STREAM_MODE_READ) == MZ_STREAM_OK)
    {
        create_compress(&inflate_stream);
        mz_stream_set_base(inflate_stream, in_stream);

        mz_stream_open(inflate_stream, NULL, MZ_STREAM_MODE_READ);
        read = mz_stream_read(inflate_stream, buf, UINT16_MAX);
        mz_stream_close(inflate_stream);

        total_in = mz_stream_get_total_in(inflate_stream);
        total_out = mz_stream_get_total_out(inflate_stream);

        mz_stream_delete(&inflate_stream);

        mz_stream_os_close(in_stream);

        printf("%s uncompressed from %d to %d\n", filename, (uint32_t)total_in, (uint32_t)total_out);
    }

    mz_stream_os_delete(&in_stream);
    mz_stream_os_create(&out_stream);

    snprintf(filename, sizeof(filename), "LICENSE.inflate.%s", method);
    if (mz_stream_os_open(out_stream, filename, MZ_STREAM_MODE_CREATE | MZ_STREAM_MODE_WRITE) == MZ_STREAM_OK)
    {
        mz_stream_crc32_create(&crc_in_stream);
        mz_stream_crc32_open(crc_in_stream, NULL, MZ_STREAM_MODE_WRITE);

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

void test_aes()
{
    test_encrypt("aes", mz_stream_aes_create, "hello");
}

void test_crypt()
{
    test_encrypt("crypt", mz_stream_crypt_create, "hello");
}

void test_zlib()
{
    test_compress("zlib", mz_stream_zlib_create);
}

void test_bzip()
{
    test_compress("bzip", mz_stream_bzip_create);
}