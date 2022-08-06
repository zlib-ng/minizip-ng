/* test_stream_compress.cc - Test basic compression
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_strm_os.h"

#ifdef HAVE_BZIP2
#  include "mz_strm_bzip.h"
#endif
#ifdef HAVE_LZMA
#  include "mz_strm_lzma.h"
#endif
#ifdef HAVE_ZLIB
#  include "mz_strm_zlib.h"
#endif
#ifdef HAVE_ZSTD
#  include "mz_strm_zstd.h"
#endif

#include <gtest/gtest.h>

static void test_compare_stream_to_end(void *source1, void *source2) {
    uint8_t source1_buf[4096];
    uint8_t source2_buf[4096];
    int32_t source1_read = 0;
    int32_t source2_read = 0;

    do {
        source1_read = mz_stream_read(source1, source1_buf, sizeof(source1_buf));
        source2_read = mz_stream_read(source2, source2_buf, sizeof(source2_buf));

        EXPECT_EQ(source1_read, source2_read);
        if (source1_read <= 0)
            break;

        EXPECT_EQ(memcmp(source1_buf, source2_buf, source1_read), 0);
    } while (1);
}

static void test_compress(const char *method, mz_stream_create_cb create_compress) {
    int64_t total_in = 0;
    int64_t total_out = 0;
    void *org_stream = NULL;
    void *compress_stream = NULL;
    void *uncompress_stream = NULL;
    void *deflate_stream = NULL;
    void *inflate_stream = NULL;

    /* Open file to be compressed */
    mz_stream_os_create(&org_stream);
    ASSERT_EQ(mz_stream_os_open(org_stream, "LICENSE", MZ_OPEN_MODE_READ), MZ_OK);

    /* Compress data into memory stream */
    mz_stream_mem_create(&compress_stream);
    ASSERT_EQ(mz_stream_mem_open(compress_stream, NULL, MZ_OPEN_MODE_CREATE), MZ_OK);

    create_compress(&deflate_stream);
    mz_stream_set_base(deflate_stream, compress_stream);

    /* Copy data from file stream and write to compression stream */
    mz_stream_open(deflate_stream, NULL, MZ_OPEN_MODE_WRITE);
    mz_stream_copy_stream_to_end(deflate_stream, NULL, org_stream, NULL);
    mz_stream_close(deflate_stream);

    mz_stream_get_prop_int64(deflate_stream, MZ_STREAM_PROP_TOTAL_IN, &total_in);
    EXPECT_EQ(total_in, mz_stream_tell(org_stream));

    mz_stream_get_prop_int64(deflate_stream, MZ_STREAM_PROP_TOTAL_OUT, &total_out);
    EXPECT_EQ(total_out, mz_stream_tell(compress_stream));

    mz_stream_delete(&deflate_stream);

    printf("%s compressed from %u to %u\n", method, (uint32_t)total_in, (uint32_t)total_out);

    /* Decompress data into memory stream */
    mz_stream_mem_create(&uncompress_stream);
    ASSERT_EQ(mz_stream_mem_open(uncompress_stream, NULL, MZ_OPEN_MODE_CREATE), MZ_OK);

    mz_stream_seek(compress_stream, 0, MZ_SEEK_SET);

    create_compress(&inflate_stream);
    mz_stream_set_base(inflate_stream, compress_stream);

    mz_stream_open(inflate_stream, NULL, MZ_OPEN_MODE_READ);
    mz_stream_copy_stream_to_end(uncompress_stream, NULL, inflate_stream, NULL);
    mz_stream_close(inflate_stream);

    mz_stream_get_prop_int64(inflate_stream, MZ_STREAM_PROP_TOTAL_IN, &total_in);
    EXPECT_EQ(total_in, mz_stream_tell(compress_stream));

    mz_stream_get_prop_int64(inflate_stream, MZ_STREAM_PROP_TOTAL_OUT, &total_out);
    EXPECT_EQ(total_out, mz_stream_tell(uncompress_stream));

    mz_stream_delete(&inflate_stream);

    printf("%s uncompressed from %u to %u\n", method, (uint32_t)total_in, (uint32_t)total_out);

    /* Compare uncompress stream to original file stream */
    mz_stream_seek(org_stream, 0, MZ_SEEK_SET);
    mz_stream_seek(uncompress_stream, 0, MZ_SEEK_SET);

    test_compare_stream_to_end(org_stream, uncompress_stream);

    mz_stream_mem_close(uncompress_stream);
    mz_stream_mem_delete(&uncompress_stream);

    mz_stream_mem_close(compress_stream);
    mz_stream_mem_delete(&compress_stream);

    mz_stream_os_close(org_stream);
    mz_stream_os_delete(&org_stream);
}

#ifdef HAVE_BZIP2
TEST(stream, bzip) {
    return test_compress("bzip", mz_stream_bzip_create);
}
#endif
#ifdef HAVE_LZMA
TEST(stream, lzma) {
    return test_compress("lzma", mz_stream_lzma_create);
}
#endif
#ifdef HAVE_ZLIB
TEST(stream, zlib) {
    return test_compress("zlib", mz_stream_zlib_create);
}
#endif
#ifdef HAVE_ZSTD
TEST(stream, zstd) {
    return test_compress("zstd", mz_stream_zstd_create);
}
#endif
