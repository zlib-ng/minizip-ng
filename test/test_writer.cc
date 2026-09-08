/* test_writer.cc - Test zip writer functionality
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

#include <gtest/gtest.h>

#include <fstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  include <direct.h>
#  define rmdir _rmdir
#else
#  include <unistd.h>
#endif

class zip_writer_test : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_EQ(mz_dir_make(root_path.c_str()), MZ_OK);

        std::ofstream entry(entry_path);
        ASSERT_TRUE(entry.is_open());
        entry << std::string(4096, 'a');
    }

    void TearDown() override {
        if (writer) {
            mz_zip_writer_close(writer);
            mz_zip_writer_delete(&writer);
        }

        mz_os_unlink(archive_path.c_str());
        mz_os_unlink(entry_path.c_str());
        rmdir(root_path.c_str());
    }

    /* Lists the names of every entry in the archive */
    std::vector<std::string> read_entry_names() {
        std::vector<std::string> names;
        mz_zip_file *file_info = nullptr;
        void *reader = mz_zip_reader_create();
        int32_t err = MZ_OK;

        EXPECT_NE(reader, nullptr);
        EXPECT_EQ(mz_zip_reader_open_file(reader, archive_path.c_str()), MZ_OK);

        err = mz_zip_reader_goto_first_entry(reader);
        while (err == MZ_OK) {
            EXPECT_EQ(mz_zip_reader_entry_get_info(reader, &file_info), MZ_OK);
            names.push_back(file_info->filename);
            err = mz_zip_reader_goto_next_entry(reader);
        }

        mz_zip_reader_close(reader);
        mz_zip_reader_delete(&reader);
        return names;
    }

    void *writer = nullptr;
    std::string root_path = "zip_writer_test";
    std::string entry_path = root_path + "/entry.txt";
    std::string archive_path = root_path + "/archive.zip";
};

TEST_F(zip_writer_test, skips_archive_stored_in_added_directory) {
    writer = mz_zip_writer_create();
    ASSERT_NE(writer, nullptr);
    ASSERT_EQ(mz_zip_writer_open_file(writer, archive_path.c_str(), 0, 0), MZ_OK);

    /* Walk the directory as "." does, so the archive is reached by a different path */
    ASSERT_EQ(mz_zip_writer_add_path(writer, (root_path + "/.").c_str(), nullptr, 0, 1), MZ_OK);
    ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
    mz_zip_writer_delete(&writer);

    EXPECT_EQ(read_entry_names(), std::vector<std::string>{"entry.txt"});
}

TEST_F(zip_writer_test, skips_archive_added_by_file) {
    writer = mz_zip_writer_create();
    ASSERT_NE(writer, nullptr);
    ASSERT_EQ(mz_zip_writer_open_file(writer, archive_path.c_str(), 0, 0), MZ_OK);

    EXPECT_EQ(mz_zip_writer_add_file(writer, archive_path.c_str(), "archive.zip"), MZ_OK);
    ASSERT_EQ(mz_zip_writer_add_file(writer, entry_path.c_str(), "entry.txt"), MZ_OK);
    ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
    mz_zip_writer_delete(&writer);

    EXPECT_EQ(read_entry_names(), std::vector<std::string>{"entry.txt"});
}
