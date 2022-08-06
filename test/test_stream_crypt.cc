/* test_stream_crypt.cc - Test encryption stream functionality
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_os.h"
#include "mz_strm_pkcrypt.h"
#include "mz_strm_wzaes.h"

#include <gtest/gtest.h>

#include <stdio.h> /* printf, snprintf */

#if defined(_MSC_VER) && (_MSC_VER < 1900)
#  define snprintf _snprintf
#endif

static void test_encrypt(const char *path, const char *method, mz_stream_create_cb crypt_create, const char *password) {
    char org_buf[4096];
    char mod_buf[4096];
    int32_t read = 0;
    int32_t written = 0;
    int64_t total_written = 0;
    void *out_stream = NULL;
    void *in_stream = NULL;
    void *crypt_out_stream = NULL;
    char encrypt_path[256];
    char decrypt_path[256];

    snprintf(encrypt_path, sizeof(encrypt_path), "%s.enc.%s", path, method);
    snprintf(decrypt_path, sizeof(decrypt_path), "%s.dec.%s", path, method);

    /* Read file to encrypt into memory buffer */
    mz_stream_os_create(&in_stream);
    EXPECT_EQ(mz_stream_os_open(in_stream, path, MZ_OPEN_MODE_READ), MZ_OK);
    {
        read = mz_stream_os_read(in_stream, org_buf, sizeof(org_buf));
        mz_stream_os_close(in_stream);
    }
    mz_stream_os_delete(&in_stream);
    EXPECT_GT(read, 0);

    /* Encrypt data to disk */
    mz_stream_os_create(&out_stream);
    EXPECT_EQ(mz_stream_os_open(out_stream, encrypt_path, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE), MZ_OK);
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, out_stream);

        EXPECT_EQ(mz_stream_open(crypt_out_stream, password, MZ_OPEN_MODE_WRITE), MZ_OK);
        {
            written = mz_stream_write(crypt_out_stream, org_buf, read);
            mz_stream_close(crypt_out_stream);
            mz_stream_get_prop_int64(crypt_out_stream, MZ_STREAM_PROP_TOTAL_OUT, &total_written);
        }

        mz_stream_delete(&crypt_out_stream);
        mz_stream_os_close(out_stream);
    }
    mz_stream_os_delete(&out_stream);
    EXPECT_GT(written, 0);

    /* Decrypt data from disk */
    mz_stream_os_create(&in_stream);
    EXPECT_EQ(mz_stream_os_open(in_stream, encrypt_path, MZ_OPEN_MODE_READ), MZ_OK);
    {
        crypt_create(&crypt_out_stream);

        mz_stream_set_base(crypt_out_stream, in_stream);
        mz_stream_set_prop_int64(crypt_out_stream, MZ_STREAM_PROP_TOTAL_IN_MAX, total_written);

        EXPECT_EQ(mz_stream_open(crypt_out_stream, password, MZ_OPEN_MODE_READ), MZ_OK);
        {
            ASSERT_LE(read, sizeof(mod_buf));
            read = mz_stream_read(crypt_out_stream, mod_buf, read);
            mz_stream_close(crypt_out_stream);
        }

        mz_stream_delete(&crypt_out_stream);
        mz_stream_os_close(in_stream);
    }
    mz_stream_os_delete(&in_stream);
    EXPECT_GT(read, 0);

    /* Write out decrypted contents to disk for debugging */
    mz_stream_os_create(&out_stream);
    EXPECT_EQ(mz_stream_os_open(out_stream, decrypt_path, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE), MZ_OK);
    {
        mz_stream_os_write(out_stream, mod_buf, read);
        mz_stream_os_close(out_stream);
    }
    mz_stream_os_delete(&out_stream);

    /* Compare original and modified buffers */
    EXPECT_EQ(memcmp(org_buf, mod_buf, read), 0);
}

#ifdef HAVE_PKCRYPT
TEST(encrypt, pkcrypt) {
    test_encrypt("LICENSE", "pkcrypt", mz_stream_pkcrypt_create, "hello");
}
#endif

#ifdef HAVE_WZAES
TEST(encrypt, aes) {
    test_encrypt("LICENSE", "aes", mz_stream_wzaes_create, "hello");
}
#endif
