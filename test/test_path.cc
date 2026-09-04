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
#include <cstdlib>
#include <cstring>
#include <gtest/gtest.h>

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

struct combine_safe_param {
    const char *base;
    const char *join;
    const char *expected_path; /* nullptr when the join is expected to be rejected */

    friend std::ostream &operator<<(std::ostream &os, const combine_safe_param &param) {
        return os << "base: " << param.base << " join: " << param.join;
    }
};

constexpr combine_safe_param combine_safe_tests[] = {
    /* Relative joins are combined unchanged */
    {"dest",     "sub\\file",   "dest\\sub\\file"},
    /* Leading separators and drive letters are stripped so the join stays relative */
    {"dest", "\\etc\\passwd", "dest\\etc\\passwd"},
    {"dest",       "\\\\\\a",           "dest\\a"},
    {"dest",      "c:\\evil",        "dest\\evil"},
    /* An empty base keeps the stripped join */
    {    "",      "\\abs\\f",            "abs\\f"},
    /* A join that strips down to nothing is rejected */
    {"dest",            "\\",             nullptr},
    {"dest",              "",             nullptr},
};

class path_combine_safe : public ::testing::TestWithParam<combine_safe_param> {};

INSTANTIATE_TEST_SUITE_P(os, path_combine_safe, testing::ValuesIn(combine_safe_tests));

TEST_P(path_combine_safe, os) {
    const auto &param = GetParam();
    std::string base = param.base;
    std::string join = param.join;
    std::string expected_path = param.expected_path ? param.expected_path : "";

    if (!mz_os_is_dir_separator('\\')) {
        std::replace(base.begin(), base.end(), '\\', '/');
        std::replace(join.begin(), join.end(), '\\', '/');
        std::replace(expected_path.begin(), expected_path.end(), '\\', '/');
    }

    char output[256];
    memset(output, 0, sizeof(output));
    strncpy(output, base.c_str(), sizeof(output) - 1);

    int32_t err = mz_path_combine_safe(output, join.c_str(), sizeof(output));
    if (param.expected_path) {
        EXPECT_EQ(err, MZ_OK);
        EXPECT_STREQ(output, expected_path.c_str());
    } else {
        EXPECT_NE(err, MZ_OK);
    }
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

/* An overlong target must be validated in full rather than truncated to a safe prefix. The
   traversal is placed past 1024 bytes so a fixed-size buffer would drop it and pass the check. */
TEST(symlink_target_base, rejects_overlong_escaping_target) {
    std::string target(1100, 'a');
    target += "/../../outside/escaped.txt";

    int32_t err = mz_path_is_symlink_target_safe("base/link", target.c_str(), "base");
    EXPECT_NE(err, MZ_OK);
}
