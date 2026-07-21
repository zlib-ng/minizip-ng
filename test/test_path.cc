/* test_path.cc - Test path functionality
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

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>

#if !defined(_WIN32) && defined(HAVE_SYMLINK)
#  include <sys/stat.h>
#  include <unistd.h>
#endif

struct resolve_path_param {
    const char *path;
    const char *expected_path;

    friend std::ostream &operator<<(std::ostream &os, const resolve_path_param &param) {
        return os << "path: " << param.path;
    }
};

constexpr resolve_path_param resolve_path_tests[] = {
    {                       "c:\\test\\.",             "c:\\test\\"},
    {                     "c:\\test\\.\\",             "c:\\test\\"},
    {                    "c:\\test\\.\\.",             "c:\\test\\"},
    {                      "c:\\test\\..",                   "c:\\"},
    {                    "c:\\test\\..\\",                   "c:\\"},
    {                   "c:\\test\\.\\..",                   "c:\\"},
    {                 "c:\\test\\.\\\\..",                   "c:\\"},
    {                                 ".",                      "."},
    {                               ".\\",                       ""},
    {                                "..",                       ""},
    {                              "..\\",                       ""},
    {                      ".\\test\\123",              "test\\123"},
    {                  ".\\..\\test\\123",              "test\\123"},
    {                 "..\\..\\test\\123",              "test\\123"},
    {                    "test\\.abc.txt",         "test\\.abc.txt"},
    {         "c:\\test\\123\\.\\abc.txt", "c:\\test\\123\\abc.txt"},
    {        "c:\\test\\123\\..\\abc.txt",      "c:\\test\\abc.txt"},
    {    "c:\\test\\123\\..\\..\\abc.txt",            "c:\\abc.txt"},
    {"c:\\test\\123\\..\\..\\..\\abc.txt",                "abc.txt"},
    { "c:\\test\\123\\..\\.\\..\\abc.txt",            "c:\\abc.txt"},
};

class path_resolve : public ::testing::TestWithParam<resolve_path_param> {};

INSTANTIATE_TEST_SUITE_P(os, path_resolve, testing::ValuesIn(resolve_path_tests));

TEST_P(path_resolve, os) {
    const auto &param = GetParam();
    std::string path = param.path;
    std::string expected_path = param.expected_path;
    char output[256];

    memset(output, 'z', sizeof(output));
    // archiving and unarchiving data on a system should preserve its structure
    if (!mz_os_is_dir_separator('\\')) {
        std::replace(path.begin(), path.end(), '\\', '/');
        std::replace(expected_path.begin(), expected_path.end(), '\\', '/');
    }
    mz_path_resolve(path.c_str(), output, sizeof(output));
    EXPECT_STREQ(output, expected_path.c_str());
}

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
#endif

struct symlink_base_param {
    const char *link_path;
    const char *target;
    const char *base_path;
    bool safe;

    friend std::ostream &operator<<(std::ostream &os, const symlink_base_param &param) {
        return os << "link: " << param.link_path << " target: " << param.target;
    }
};

constexpr symlink_base_param symlink_base_tests[] = {
    /* In-bounds targets are allowed */
    {      "base\\link",          "inside.txt", "base",  true},
    { "base\\sub\\link",      "..\\inside.txt", "base",  true},
    {      "base\\link",            "..\\base", "base",  true},
    /* Targets that resolve outside the base are rejected */
    {      "base\\link",         "..\\out.txt", "base", false},
    {"base\\a\\b\\link", "..\\..\\..\\out.txt", "base", false},
    /* Absolute targets are rejected */
    {      "base\\link",       "\\etc\\passwd", "base", false},
    /* A sibling directory sharing the base name prefix is not in base */
    {      "base\\link",    "..\\base_evil\\x", "base", false},
};

class symlink_target_base : public ::testing::TestWithParam<symlink_base_param> {};

INSTANTIATE_TEST_SUITE_P(os, symlink_target_base, testing::ValuesIn(symlink_base_tests));

TEST_P(symlink_target_base, os) {
    const auto &param = GetParam();
    std::string link_path = param.link_path;
    std::string target = param.target;
    std::string base_path = param.base_path;

    if (!mz_os_is_dir_separator('\\')) {
        std::replace(link_path.begin(), link_path.end(), '\\', '/');
        std::replace(target.begin(), target.end(), '\\', '/');
        std::replace(base_path.begin(), base_path.end(), '\\', '/');
    }

    int32_t err = mz_path_is_symlink_target_safe(link_path.c_str(), target.c_str(), base_path.c_str());
    if (param.safe)
        EXPECT_EQ(err, MZ_OK);
    else
        EXPECT_NE(err, MZ_OK);
}
