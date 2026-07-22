/* test_encoding.cc - Test string encoding
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

#include <gtest/gtest.h>

TEST(os, utf8_unicode_string) {
    const char *test_string = "Heiz�lr�cksto�abd�mpfung";
    char *utf8_string = mz_os_utf8_string_create(test_string, MZ_ENCODING_CODEPAGE_950);
    ASSERT_NE(utf8_string, nullptr);
#if defined(_WIN32)
    wchar_t *unicode_string = mz_os_unicode_string_create(utf8_string, MZ_ENCODING_UTF8);
    ASSERT_NE(unicode_string, nullptr);
    mz_os_unicode_string_delete(&unicode_string);
#endif
    mz_os_utf8_string_delete(&utf8_string);
}

TEST(os, utf8_string_validation) {
    const char legacy_filename[] = "final_report_realfinal_"
                                   "\xc1\xf8\xc2\xa5\xc3\xd6\xc1\xbe"
                                   ".docx";
    const char utf8_filename[] = "final_report_realfinal_"
                                 "\xec\xa7\x84\xec\xa7\x9c\xec\xb5\x9c\xec\xa2\x85"
                                 ".docx";

    EXPECT_EQ(MZ_DATA_ERROR, mz_os_utf8_string_is_valid(legacy_filename));
    EXPECT_EQ(MZ_OK, mz_os_utf8_string_is_valid(utf8_filename));
}

#if GTEST_OS_WINDOWS
TEST(zip_reader, pattern_matches_legacy_encoded_filename) {
    const char legacy_filename[] = "final_report_realfinal_"
                                   "\xc1\xf8\xc2\xa5\xc3\xd6\xc1\xbe"
                                   ".docx";
    const char utf8_filename[] = "final_report_realfinal_"
                                 "\xec\xa7\x84\xec\xa7\x9c\xec\xb5\x9c\xec\xa2\x85"
                                 ".docx";
    const char contents[] = "test";
    const void *zip_buffer = NULL;
    void *mem_stream = mz_stream_mem_create();
    void *writer = mz_zip_writer_create();
    void *reader = mz_zip_reader_create();
    mz_zip_file file_info = {};
    int32_t zip_buffer_length = 0;

    ASSERT_NE(nullptr, mem_stream);
    ASSERT_NE(nullptr, writer);
    ASSERT_NE(nullptr, reader);
    ASSERT_EQ(MZ_OK, mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE));
    ASSERT_EQ(MZ_OK, mz_zip_writer_open(writer, mem_stream, 0));

    file_info.filename = legacy_filename;
    file_info.version_madeby = MZ_VERSION_MADEBY;
    file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
    ASSERT_EQ(MZ_OK, mz_zip_writer_add_buffer(writer, contents, sizeof(contents) - 1, &file_info));
    ASSERT_EQ(MZ_OK, mz_zip_writer_close(writer));

    mz_stream_mem_get_buffer(mem_stream, &zip_buffer);
    mz_stream_mem_get_buffer_length(mem_stream, &zip_buffer_length);
    ASSERT_NE(nullptr, zip_buffer);
    ASSERT_GT(zip_buffer_length, 0);

    mz_zip_reader_set_encoding(reader, MZ_ENCODING_CODEPAGE_949);
    ASSERT_EQ(MZ_OK, mz_zip_reader_open_buffer(reader, (const uint8_t *)zip_buffer, zip_buffer_length, 1));
    mz_zip_reader_set_pattern(reader, utf8_filename, 1);
    EXPECT_EQ(MZ_OK, mz_zip_reader_goto_first_entry(reader));

    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);
    mz_zip_writer_delete(&writer);
    mz_stream_mem_close(mem_stream);
    mz_stream_mem_delete(&mem_stream);
}
#endif
