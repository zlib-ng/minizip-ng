/* test_path.cc - Test path functionality
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"

#include <algorithm>
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

#if !defined(_WIN32) && defined(HAVE_SYMLINK)
TEST(path_security, rejects_nested_existing_symlink_escape) {
    char temp_path[] = "/tmp/minizip-symlink-test-XXXXXX";
    char *root = mkdtemp(temp_path);
    ASSERT_NE(root, nullptr);

    std::string base = std::string(root) + "/extract";
    std::string outside = std::string(root) + "/outside";
    std::string redirect = base + "/redirect";
    std::string link = base + "/link";

    ASSERT_EQ(mkdir(base.c_str(), 0755), 0);
    ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
    ASSERT_EQ(symlink("../outside", redirect.c_str()), 0);

    EXPECT_NE(mz_path_is_symlink_target_safe(link.c_str(), "redirect", base.c_str()), MZ_OK);
    EXPECT_NE(mz_path_is_symlink_target_safe(link.c_str(), "redirect/missing", base.c_str()), MZ_OK);

    unlink(redirect.c_str());
    rmdir(outside.c_str());
    rmdir(base.c_str());
    rmdir(root);
}

TEST(path_security, rejects_existing_symlink_component_escape) {
    char temp_path[] = "/tmp/minizip-symlink-test-XXXXXX";
    char *root = mkdtemp(temp_path);
    ASSERT_NE(root, nullptr);

    std::string base = std::string(root) + "/extract";
    std::string outside = std::string(root) + "/outside";
    std::string redirect = base + "/redirect";
    std::string victim = redirect + "/victim";

    ASSERT_EQ(mkdir(base.c_str(), 0755), 0);
    ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
    ASSERT_EQ(symlink("../outside", redirect.c_str()), 0);

    EXPECT_NE(mz_dir_has_unsafe_symlink(victim.c_str(), base.c_str()), MZ_OK);

    unlink(redirect.c_str());
    rmdir(outside.c_str());
    rmdir(base.c_str());
    rmdir(root);
}
#endif
