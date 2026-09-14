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
TEST(zip_catalog, replacement_bounds) {
    struct resources {
        void *zip[2] = {};
        void *stream[2] = {};
        bool opened[2] = {};
        void *catalog = nullptr;

        ~resources() {
            for (int i = 0; i < 2; i++) {
                if (opened[i])
                    mz_zip_close(zip[i]);
                mz_zip_delete(&zip[i]);
                mz_stream_mem_delete(&stream[i]);
            }
            mz_stream_mem_delete(&catalog);
        }
    } data;

    /* The replacement's first header is longer, placing its second entry beyond the old bounds. */
    const char *names[] = {"first", "second"};
    for (int i = 0; i < 2; i++) {
        data.zip[i] = mz_zip_create();
        data.stream[i] = mz_stream_mem_create();
        ASSERT_NE(data.zip[i], nullptr);
        ASSERT_NE(data.stream[i], nullptr);
        ASSERT_EQ(mz_stream_open(data.stream[i], nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
        ASSERT_EQ(mz_zip_open(data.zip[i], data.stream[i], MZ_OPEN_MODE_WRITE), MZ_OK);
        data.opened[i] = true;

        for (int entry_index = 0; entry_index <= i; entry_index++) {
            mz_zip_file entry = {};
            entry.filename = i == 0 ? "a" : names[entry_index];
            entry.compression_method = MZ_COMPRESS_METHOD_STORE;
            ASSERT_EQ(mz_zip_entry_write_open(data.zip[i], &entry, 0, 0, nullptr), MZ_OK);
            ASSERT_EQ(mz_zip_entry_write_close(data.zip[i], 0, -1, -1), MZ_OK);
        }
    }

    /* Finish the small archive and reopen it to load its directory size from ZIP metadata. */
    int32_t err = mz_zip_close(data.zip[0]);
    data.opened[0] = false;
    ASSERT_EQ(err, MZ_OK);
    ASSERT_EQ(mz_stream_seek(data.stream[0], 0, MZ_SEEK_SET), MZ_OK);
    ASSERT_EQ(mz_zip_open(data.zip[0], data.stream[0], MZ_OPEN_MODE_READ), MZ_OK);
    data.opened[0] = true;
    ASSERT_EQ(mz_zip_goto_first_entry(data.zip[0]), MZ_OK);
    int64_t old_size = mz_stream_tell(data.stream[0]) - mz_zip_get_entry(data.zip[0]);

    void *original_catalog = nullptr;
    ASSERT_EQ(mz_zip_get_cd_mem_stream(data.zip[1], &original_catalog), MZ_OK);
    ASSERT_EQ(mz_stream_seek(original_catalog, 0, MZ_SEEK_SET), MZ_OK);
    data.catalog = mz_stream_mem_create();
    ASSERT_NE(data.catalog, nullptr);
    ASSERT_EQ(mz_stream_open(data.catalog, nullptr, MZ_OPEN_MODE_CREATE), MZ_OK);
    ASSERT_EQ(mz_stream_write(data.catalog, "prefix", 6), 6);
    ASSERT_EQ(mz_stream_copy_stream_to_end(data.catalog, nullptr, original_catalog, nullptr), MZ_OK);
    int64_t stream_end = mz_stream_tell(data.catalog);

    /* Measuring the replacement must preserve the caller's stream position. */
    ASSERT_EQ(mz_stream_seek(data.catalog, 2, MZ_SEEK_SET), MZ_OK);
    ASSERT_EQ(mz_zip_set_cd_stream(data.zip[0], 6, data.catalog), MZ_OK);
    EXPECT_EQ(mz_stream_tell(data.catalog), 2);
    ASSERT_EQ(mz_zip_set_number_entry(data.zip[0], 2), MZ_OK);

    /* Direct access must accept an entry reached sequentially beyond the old bounds. */
    ASSERT_EQ(mz_zip_goto_first_entry(data.zip[0]), MZ_OK);
    ASSERT_EQ(mz_zip_goto_next_entry(data.zip[0]), MZ_OK);
    int64_t second_pos = mz_zip_get_entry(data.zip[0]);
    ASSERT_GT(second_pos - 6, old_size);
    EXPECT_EQ(mz_zip_goto_entry(data.zip[0], second_pos), MZ_OK);
    EXPECT_EQ(mz_zip_goto_entry(data.zip[0], stream_end + 1), MZ_PARAM_ERROR);
}
#endif
