/* test_reader.cc - Test zip reader functionality
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

#include <string>

#if !defined(_WIN32) && defined(HAVE_SYMLINK)
#  include <sys/stat.h>
#  include <unistd.h>

class zip_reader_symlink_test : public ::testing::Test {
  protected:
    void SetUp() override {
        char temp_path[] = "/tmp/minizip-extract-test-XXXXXX";
        char *root = nullptr;
        mz_zip_file file_info;

        original_directory = getcwd(nullptr, 0);
        ASSERT_NE(original_directory, nullptr);

        root = mkdtemp(temp_path);
        ASSERT_NE(root, nullptr);

        root_path = root;
        archive = root_path + "/archive.zip";
        destination = root_path + "/destination";
        outside = root_path + "/outside";
        pivot = destination + "/pivot";
        escaped_directory = outside + "/newdir";

        memset(&file_info, 0, sizeof(file_info));
        file_info.filename = "pivot/newdir/";
        file_info.version_madeby = MZ_VERSION_MADEBY;
        file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
        file_info.flag = MZ_ZIP_FLAG_UTF8;

        writer = mz_zip_writer_create();
        ASSERT_NE(writer, nullptr);
        ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
        ASSERT_EQ(mz_zip_writer_add_info(writer, nullptr, nullptr, &file_info), MZ_OK);
        ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
        mz_zip_writer_delete(&writer);

        ASSERT_EQ(mkdir(destination.c_str(), 0755), 0);
        ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
        ASSERT_EQ(symlink("../outside", pivot.c_str()), 0);
    }

    void TearDown() override {
        if (reader) {
            mz_zip_reader_close(reader);
            mz_zip_reader_delete(&reader);
        }
        if (writer) {
            mz_zip_writer_close(writer);
            mz_zip_writer_delete(&writer);
        }
        if (original_directory) {
            chdir(original_directory);
            free(original_directory);
        }

        unlink(pivot.c_str());
        unlink(archive.c_str());
        rmdir(escaped_directory.c_str());
        rmdir(outside.c_str());
        rmdir(destination.c_str());
        rmdir(root_path.c_str());
    }

    void *reader = nullptr;
    void *writer = nullptr;
    char *original_directory = nullptr;
    std::string root_path;
    std::string archive;
    std::string destination;
    std::string outside;
    std::string pivot;
    std::string escaped_directory;
};

TEST_F(zip_reader_symlink_test, rejects_directory_entry_with_destination) {
    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);

    EXPECT_NE(mz_zip_reader_save_all(reader, destination.c_str()), MZ_OK);
    EXPECT_NE(mz_os_is_dir(escaped_directory.c_str()), MZ_OK);
}

TEST_F(zip_reader_symlink_test, rejects_directory_entry_without_destination) {
    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    ASSERT_EQ(chdir(destination.c_str()), 0);

    EXPECT_NE(mz_zip_reader_save_all(reader, nullptr), MZ_OK);
    EXPECT_NE(mz_os_is_dir(escaped_directory.c_str()), MZ_OK);
}
#endif
