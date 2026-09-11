/* test_finalization.cc - Test compression and ZIP entry finalization
   part of the minizip-ng project
   https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_strm.h"
#include "mz_zip.h"

#ifdef HAVE_BZIP2
#  include "mz_strm_bzip.h"
#endif
#ifdef HAVE_LIBCOMP
#  include "mz_strm_libcomp.h"
#endif
#ifdef HAVE_LZMA
#  include "mz_strm_lzma.h"
#endif
#ifdef HAVE_PPMD
#  include "mz_strm_ppmd.h"
#endif
#ifdef HAVE_ZLIB
#  include "mz_strm_zlib.h"
#endif
#ifdef HAVE_ZSTD
#  include "mz_strm_zstd.h"
#endif

#include <gtest/gtest.h>

#include <vector>

#if !defined(MZ_ZIP_NO_COMPRESSION)
/* Fail exactly one write; subsequent cleanup writes succeed. */
struct finalization_sink {
    mz_stream stream = {};
    int64_t position = 0;
    bool fail_next = false;
    int failures = 0;
    int writes_before_failure = 0;
    int32_t failed_write_size = 0;
    int writes = 0;
    mz_stream_close_cb crypt_close = nullptr;
    int32_t crypt_error = MZ_OK;
    int crypt_calls = 0;
};

static int32_t finalization_is_open(void *) {
    return MZ_OK;
}

static int32_t finalization_write(void *stream, const void *, int32_t size) {
    auto *sink = static_cast<finalization_sink *>(stream);
    sink->writes++;

    if (sink->fail_next) {
        if (sink->writes_before_failure > 0) {
            sink->writes_before_failure--;
        } else {
            sink->fail_next = false;
            sink->failures++;
            sink->failed_write_size = size;
            return MZ_WRITE_ERROR;
        }
    }

    sink->position += size;
    return size;
}

static int64_t finalization_tell(void *stream) {
    return static_cast<finalization_sink *>(stream)->position;
}

static int32_t finalization_seek(void *stream, int64_t offset, int32_t origin) {
    auto *sink = static_cast<finalization_sink *>(stream);
    sink->position = origin == MZ_SEEK_SET ? offset : sink->position + offset;
    return MZ_OK;
}

static mz_stream_vtbl finalization_vtbl = {nullptr,           finalization_is_open,
                                           nullptr,           finalization_write,
                                           finalization_tell, finalization_seek,
                                           nullptr,           nullptr,
                                           nullptr,           nullptr,
                                           nullptr,           nullptr};

struct codec_finalization_param {
    const char *name;
    mz_stream_create_cb create;
    int16_t method;
    int32_t payload_size;
    int writes_before_failure = 0;
};

const codec_finalization_param codec_finalization_cases[] = {
#  ifdef HAVE_BZIP2
    {"bzip2_final_flush", mz_stream_bzip_create, 0, 7},
    {"bzip2_full_buffer", mz_stream_bzip_create, 0, 32768},
#  endif
#  ifdef HAVE_LZMA
    {"lzma_header_flush", mz_stream_lzma_create, MZ_COMPRESS_METHOD_LZMA, 7},
    /* Let the LZMA properties header succeed, then fail the compressed data write. */
    {"lzma_data_flush", mz_stream_lzma_create, MZ_COMPRESS_METHOD_LZMA, 7, 1},
    {"xz_final_flush", mz_stream_lzma_create, MZ_COMPRESS_METHOD_XZ, 7},
    {"xz_full_buffer", mz_stream_lzma_create, MZ_COMPRESS_METHOD_XZ, 32768},
#  endif
#  ifdef HAVE_ZSTD
    {"zstd_final_flush", mz_stream_zstd_create, 0, 7},
    {"zstd_full_buffer", mz_stream_zstd_create, 0, 32768},
#  endif
#  ifdef HAVE_PPMD
    {"ppmd_final_flush", mz_stream_ppmd_create, 0, 7},
#  endif
#  ifdef HAVE_ZLIB
    {"zlib_final_flush", mz_stream_zlib_create, 0, 7},
    {"zlib_full_buffer", mz_stream_zlib_create, 0, 32768},
#  endif
#  ifdef HAVE_LIBCOMP
    {"apple_deflate_final_flush", mz_stream_libcomp_create, MZ_COMPRESS_METHOD_DEFLATE, 7},
    {"apple_deflate_full_buffer", mz_stream_libcomp_create, MZ_COMPRESS_METHOD_DEFLATE, 32768},
    {"apple_xz_final_flush", mz_stream_libcomp_create, MZ_COMPRESS_METHOD_XZ, 7},
    {"apple_xz_full_buffer", mz_stream_libcomp_create, MZ_COMPRESS_METHOD_XZ, 32768},
#  endif
};

class codec_finalization_test : public ::testing::TestWithParam<codec_finalization_param> {
  protected:
    void SetUp() override {
        const auto &param = GetParam();

        sink.stream.vtbl = &finalization_vtbl;
        codec = param.create();
        ASSERT_NE(codec, nullptr);

        if (param.method != 0)
            ASSERT_EQ(mz_stream_set_prop_int64(codec, MZ_STREAM_PROP_COMPRESS_METHOD, param.method), MZ_OK);
        ASSERT_EQ(mz_stream_set_base(codec, &sink), MZ_OK);
        ASSERT_EQ(mz_stream_open(codec, nullptr, MZ_OPEN_MODE_WRITE), MZ_OK);

        payload.resize(param.payload_size);
        uint32_t random = 1;
        for (auto &byte : payload) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = static_cast<uint8_t>(random);
        }
    }

    void TearDown() override {
        if (codec) {
            if (mz_stream_is_open(codec) == MZ_OK)
                mz_stream_close(codec);
            mz_stream_delete(&codec);
        }
    }

    finalization_sink sink;
    void *codec = nullptr;
    std::vector<uint8_t> payload;
};

INSTANTIATE_TEST_SUITE_P(stream, codec_finalization_test, testing::ValuesIn(codec_finalization_cases),
                         [](const testing::TestParamInfo<codec_finalization_param> &info) {
                             return info.param.name;
                         });

TEST_P(codec_finalization_test, preserves_write_error) {
    const auto &param = GetParam();

    ASSERT_EQ(mz_stream_write(codec, payload.data(), param.payload_size), param.payload_size);

    sink.writes_before_failure = param.writes_before_failure;
    sink.fail_next = true;
    const int writes_before_close = sink.writes;

    EXPECT_EQ(mz_stream_close(codec), MZ_WRITE_ERROR);
    EXPECT_EQ(sink.failures, 1);
    EXPECT_EQ(sink.writes, writes_before_close + param.writes_before_failure + 1);
    EXPECT_NE(mz_stream_is_open(codec), MZ_OK);

    /* Verify whether the failure occurred in a full buffer or the final short write. */
    if (param.payload_size == 7) {
        EXPECT_GT(sink.failed_write_size, 0);
        EXPECT_LT(sink.failed_write_size, INT16_MAX);
    } else {
        EXPECT_EQ(sink.failed_write_size, INT16_MAX);
    }
}

#  if defined(HAVE_ZLIB) || defined(HAVE_LIBCOMP)
struct zip_finalization_param {
    const char *name;
    bool encrypted;
    bool fail_write;
    int32_t crypt_error;
    int32_t expected_error;
};

const zip_finalization_param zip_finalization_cases[] = {
    {                        "plain_success", false, false,          MZ_OK,          MZ_OK},
    {                    "plain_write_error", false,  true,          MZ_OK, MZ_WRITE_ERROR},
#    ifdef HAVE_WZAES
    {                    "encrypted_success",  true, false,          MZ_OK,          MZ_OK},
    {                "encrypted_write_error",  true,  true,          MZ_OK, MZ_WRITE_ERROR},
    {               "encryption_close_error",  true, false, MZ_CRYPT_ERROR, MZ_CRYPT_ERROR},
    {"write_error_precedes_encryption_error",  true,  true, MZ_CRYPT_ERROR, MZ_WRITE_ERROR},
#    endif
};

#    ifdef HAVE_WZAES
static int32_t finalization_close_crypt(void *stream) {
    auto *sink = reinterpret_cast<finalization_sink *>(static_cast<mz_stream *>(stream)->base);
    sink->crypt_calls++;

    int32_t err = sink->crypt_close(stream);

    /* Run real cleanup, then inject a distinct error to check precedence. */
    return err != MZ_OK ? err : sink->crypt_error;
}
#    endif

class zip_finalization_test : public ::testing::TestWithParam<zip_finalization_param> {
  protected:
    void SetUp() override {
        const auto &param = GetParam();

        sink.stream.vtbl = &finalization_vtbl;
        zip = mz_zip_create();
        ASSERT_NE(zip, nullptr);
        ASSERT_EQ(mz_zip_open(zip, &sink, MZ_OPEN_MODE_WRITE), MZ_OK);
        zip_opened = true;

        mz_zip_file entry = {};
        entry.filename = "entry";
        entry.compression_method = MZ_COMPRESS_METHOD_DEFLATE;
        if (param.encrypted) {
            entry.flag = MZ_ZIP_FLAG_ENCRYPTED;
            entry.aes_version = 2;
            entry.aes_strength = 3;
        }

        ASSERT_EQ(mz_zip_entry_write_open(zip, &entry, 6, 0, param.encrypted ? "password" : nullptr), MZ_OK);
        ASSERT_EQ(mz_zip_entry_write(zip, "payload", 7), 7);

#    ifdef HAVE_WZAES
        if (param.encrypted) {
            void *compress = nullptr;
            ASSERT_EQ(mz_zip_entry_get_compress_stream(zip, &compress), MZ_OK);
            mz_stream *crypt = static_cast<mz_stream *>(compress)->base;

            crypt_vtbl = *crypt->vtbl;
            sink.crypt_close = crypt_vtbl.close;
            sink.crypt_error = param.crypt_error;
            crypt_vtbl.close = finalization_close_crypt;
            crypt->vtbl = &crypt_vtbl;
        }
#    endif
    }

    void TearDown() override {
        if (zip) {
            if (zip_opened)
                mz_zip_close(zip);
            mz_zip_delete(&zip);
        }
    }

    finalization_sink sink;
    void *zip = nullptr;
    bool zip_opened = false;
    mz_stream_vtbl crypt_vtbl = {};
};

INSTANTIATE_TEST_SUITE_P(zip, zip_finalization_test, testing::ValuesIn(zip_finalization_cases),
                         [](const testing::TestParamInfo<zip_finalization_param> &info) {
                             return info.param.name;
                         });

TEST_P(zip_finalization_test, preserves_close_error) {
    const auto &param = GetParam();

    sink.fail_next = param.fail_write;

    EXPECT_EQ(mz_zip_entry_write_close(zip, 0, -1, -1), param.expected_error);
    EXPECT_EQ(sink.failures, param.fail_write ? 1 : 0);
    EXPECT_NE(mz_zip_entry_is_open(zip), MZ_OK);
    if (param.encrypted)
        EXPECT_EQ(sink.crypt_calls, 1);

    /* Cleanup is required, but a failed entry does not promise a valid archive. */
    int32_t close_error = mz_zip_close(zip);
    zip_opened = false;
    if (param.expected_error == MZ_OK)
        EXPECT_EQ(close_error, MZ_OK);
}
#  endif
#endif
