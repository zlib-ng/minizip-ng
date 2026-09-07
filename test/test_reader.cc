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

#include <cstdlib>
#include <cstring>
#include <string>

#if !defined(_WIN32)
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#if !defined(_WIN32) && defined(HAVE_SYMLINK)

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

class zip_reader_confinement_test : public ::testing::Test {
  protected:
    void SetUp() override {
        char temp_path[] = "/tmp/minizip-confine-test-XXXXXX";
        char *root = nullptr;

        original_directory = getcwd(nullptr, 0);
        ASSERT_NE(original_directory, nullptr);

        root = mkdtemp(temp_path);
        ASSERT_NE(root, nullptr);

        root_path = root;
        archive = root_path + "/archive.zip";
        destination = root_path + "/destination";
        outside = root_path + "/outside";

        ASSERT_EQ(mkdir(destination.c_str(), 0755), 0);
        ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
    }

    void TearDown() override {
        if (reader) {
            mz_zip_reader_close(reader);
            mz_zip_reader_delete(&reader);
        }
        if (original_directory) {
            chdir(original_directory);
            free(original_directory);
        }
        /* Extraction may create a nested tree under the destination, so remove it recursively */
        std::string command = "rm -rf " + root_path;
        (void)system(command.c_str());
    }

    /* Write a single stored entry with the given name and contents */
    void write_entry(const char *filename, const char *contents) {
        mz_zip_file file_info;
        void *writer = mz_zip_writer_create();
        ASSERT_NE(writer, nullptr);

        memset(&file_info, 0, sizeof(file_info));
        file_info.filename = filename;
        file_info.version_madeby = MZ_VERSION_MADEBY;
        file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
        file_info.flag = MZ_ZIP_FLAG_UTF8;

        ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
        ASSERT_EQ(mz_zip_writer_add_buffer(writer, (void *)contents, (int32_t)strlen(contents), &file_info), MZ_OK);
        ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
        mz_zip_writer_delete(&writer);
    }

    void *reader = nullptr;
    char *original_directory = nullptr;
    std::string root_path;
    std::string archive;
    std::string destination;
    std::string outside;
};

TEST_F(zip_reader_confinement_test, does_not_write_through_dangling_symlink) {
    std::string planted = destination + "/link_name";
    std::string escaped = outside + "/pwned.txt";

    /* Pre-plant a dangling symlink whose target does not yet exist */
    ASSERT_EQ(symlink(escaped.c_str(), planted.c_str()), 0);

    write_entry("link_name", "escape");

    reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    EXPECT_EQ(mz_zip_reader_save_all(reader, destination.c_str()), MZ_OK);

    /* Extraction must not follow the symlink to write outside the destination */
    EXPECT_NE(mz_os_file_exists(escaped.c_str()), MZ_OK);
    EXPECT_NE(mz_os_is_symlink(planted.c_str()), MZ_OK);
    EXPECT_EQ(mz_os_file_exists(planted.c_str()), MZ_OK);

    unlink(planted.c_str());
    unlink(archive.c_str());
}
#endif

#if !defined(_WIN32)
/* A crafted archive must not produce a setuid file on extraction */
TEST(zip_reader_attribs, strips_setuid_bits) {
    char destination[] = "/tmp/minizip-attribs-test-XXXXXX";
    ASSERT_NE(mkdtemp(destination), nullptr);

    std::string archive = std::string(destination) + "/archive.zip";
    std::string extracted = std::string(destination) + "/setuid_entry";

    mz_zip_file file_info;
    memset(&file_info, 0, sizeof(file_info));
    file_info.filename = "setuid_entry";
    file_info.version_madeby = (MZ_HOST_SYSTEM_UNIX << 8) | MZ_VERSION_MADEBY_ZIP_VERSION;
    file_info.compression_method = MZ_COMPRESS_METHOD_STORE;
    file_info.flag = MZ_ZIP_FLAG_UTF8;
    file_info.external_fa = (uint32_t)((S_ISUID | S_ISGID | S_ISVTX | 0755) << 16);

    void *writer = mz_zip_writer_create();
    ASSERT_NE(writer, nullptr);
    ASSERT_EQ(mz_zip_writer_open_file(writer, archive.c_str(), 0, 0), MZ_OK);
    ASSERT_EQ(mz_zip_writer_add_buffer(writer, (void *)"data", 4, &file_info), MZ_OK);
    ASSERT_EQ(mz_zip_writer_close(writer), MZ_OK);
    mz_zip_writer_delete(&writer);

    void *reader = mz_zip_reader_create();
    ASSERT_NE(reader, nullptr);
    ASSERT_EQ(mz_zip_reader_open_file(reader, archive.c_str()), MZ_OK);
    EXPECT_EQ(mz_zip_reader_save_all(reader, destination), MZ_OK);
    mz_zip_reader_close(reader);
    mz_zip_reader_delete(&reader);

    struct stat entry_stat;
    memset(&entry_stat, 0, sizeof(entry_stat));
    ASSERT_EQ(stat(extracted.c_str(), &entry_stat), 0);

    /* The special bits are stripped while the ordinary permission bits are kept */
    EXPECT_EQ(entry_stat.st_mode & (S_ISUID | S_ISGID | S_ISVTX), 0u);
    EXPECT_EQ(entry_stat.st_mode & 0777, 0755u);

    unlink(extracted.c_str());
    unlink(archive.c_str());
    rmdir(destination);
}
#endif
