/* test_zip_catalog.cc - Test central directory handling
   part of the minizip-ng project
   https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_zip.h"

#include <gtest/gtest.h>

#ifndef MZ_ZIP_NO_COMPRESSION
class zip_catalog_test : public ::testing::Test {
  protected:
    void *writer = nullptr;
    bool writer_opened = false;
    bool source_opened = false;
    bool target_opened = false;
    void *small = nullptr;
    void *large = nullptr;
    void *source = nullptr;
    void *target = nullptr;
    void *catalog = nullptr;
    int64_t source_start = 0;
    int64_t last_offset = 0;
    int64_t catalog_size = 0;

    void make_archive(void **memory, int count) {
        *memory = mz_stream_mem_create();
        ASSERT_NE(*memory, nullptr);
        writer = mz_zip_create();
        ASSERT_NE(writer, nullptr);

        ASSERT_EQ(mz_stream_open(*memory, nullptr, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_READWRITE), MZ_OK);
        ASSERT_EQ(mz_zip_open(writer, *memory, MZ_OPEN_MODE_WRITE), MZ_OK);
        writer_opened = true;

        for (int i = 0; i < count; i++) {
            char name[] = "entry0";
            name[5] += i;

            mz_zip_file entry = {};
            entry.filename = name;
            entry.compression_method = MZ_COMPRESS_METHOD_STORE;

            ASSERT_EQ(mz_zip_entry_write_open(writer, &entry, 0, 0, nullptr), MZ_OK);
            ASSERT_EQ(mz_zip_entry_write_close(writer, 0, -1, -1), MZ_OK);
        }

        int32_t err = mz_zip_close(writer);
        writer_opened = false;
        ASSERT_EQ(err, MZ_OK);
        mz_zip_delete(&writer);

        ASSERT_EQ(mz_stream_seek(*memory, 0, MZ_SEEK_SET), MZ_OK);
    }

    void SetUp() override {
        ASSERT_NO_FATAL_FAILURE(make_archive(&small, 1));
        ASSERT_NO_FATAL_FAILURE(make_archive(&large, 3));

        source = mz_zip_create();
        ASSERT_NE(source, nullptr);
        target = mz_zip_create();
        ASSERT_NE(target, nullptr);
        catalog = mz_stream_mem_create();
        ASSERT_NE(catalog, nullptr);

        ASSERT_EQ(mz_zip_open(source, large, MZ_OPEN_MODE_READ), MZ_OK);
        source_opened = true;
        ASSERT_EQ(mz_zip_open(target, small, MZ_OPEN_MODE_READ), MZ_OK);
        target_opened = true;

        ASSERT_EQ(mz_zip_goto_first_entry(source), MZ_OK);
        source_start = mz_zip_get_entry(source);
        ASSERT_EQ(mz_zip_goto_next_entry(source), MZ_OK);
        ASSERT_EQ(mz_zip_goto_next_entry(source), MZ_OK);
        last_offset = mz_zip_get_entry(source) - source_start;
        catalog_size = mz_stream_tell(large) - source_start;

        ASSERT_EQ(mz_stream_open(catalog, nullptr, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_READWRITE), MZ_OK);
    }

    void TearDown() override {
        if (writer) {
            if (writer_opened)
                mz_zip_close(writer);
            mz_zip_delete(&writer);
        }

        if (target) {
            if (target_opened)
                mz_zip_close(target);
            mz_zip_delete(&target);
        }

        if (source) {
            if (source_opened)
                mz_zip_close(source);
            mz_zip_delete(&source);
        }

        mz_stream_mem_delete(&catalog);
        mz_stream_mem_delete(&large);
        mz_stream_mem_delete(&small);
    }

    void check_replacement(int64_t prefix) {
        for (int64_t i = 0; i < prefix; i++)
            ASSERT_EQ(mz_stream_write_uint8(catalog, 0), MZ_OK);
        ASSERT_EQ(mz_stream_seek(large, source_start, MZ_SEEK_SET), MZ_OK);
        ASSERT_EQ(mz_stream_copy(catalog, large, static_cast<int32_t>(catalog_size)), MZ_OK);

        int64_t stream_end = mz_stream_tell(catalog);
        ASSERT_EQ(mz_stream_seek(catalog, 2, MZ_SEEK_SET), MZ_OK);
        ASSERT_EQ(mz_zip_set_cd_stream(target, prefix, catalog), MZ_OK);
        EXPECT_EQ(mz_stream_tell(catalog), 2);
        EXPECT_EQ(mz_zip_goto_entry(target, stream_end + 1), MZ_PARAM_ERROR);
        ASSERT_EQ(mz_zip_set_number_entry(target, 3), MZ_OK);

        ASSERT_EQ(mz_zip_goto_first_entry(target), MZ_OK);
        ASSERT_EQ(mz_zip_goto_next_entry(target), MZ_OK);
        ASSERT_EQ(mz_zip_goto_next_entry(target), MZ_OK);
        EXPECT_EQ(mz_zip_get_entry(target), prefix + last_offset);

        ASSERT_EQ(mz_zip_goto_entry(target, prefix + last_offset), MZ_OK);
        mz_zip_file *info = nullptr;
        ASSERT_EQ(mz_zip_entry_get_info(target, &info), MZ_OK);
        EXPECT_STREQ(info->filename, "entry2");
    }
};

TEST_F(zip_catalog_test, replacement_bounds) {
    check_replacement(0);
}

TEST_F(zip_catalog_test, replacement_with_nonzero_start) {
    check_replacement(17);
}
#endif
