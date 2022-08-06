/* test_path.cc - Test path functionality
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"

#include <gtest/gtest.h>

struct resolve_path_param {
    const char *path;
    const char *expected_path;

    friend std::ostream &operator<<(std::ostream &os, const resolve_path_param &param) {
        return os << "path: " << param.path;
    }
};

constexpr resolve_path_param resolve_path_tests[] = {
    { "c:\\test\\.", "c:\\test\\" },
    { "c:\\test\\.\\", "c:\\test\\" },
    { "c:\\test\\.\\.", "c:\\test\\" },
    { "c:\\test\\..", "c:\\" },
    { "c:\\test\\..\\", "c:\\" },
    { "c:\\test\\.\\..", "c:\\" },
    { "c:\\test\\.\\\\..", "c:\\" },
    { ".", "." },
    { ".\\", "" },
    { "..", "" },
    { "..\\", "" },
    { ".\\test\\123", "test\\123" },
    { ".\\..\\test\\123", "test\\123" },
    { "..\\..\\test\\123", "test\\123" },
    { "test\\.abc.txt", "test\\.abc.txt" },
    { "c:\\test\\123\\.\\abc.txt", "c:\\test\\123\\abc.txt" },
    { "c:\\test\\123\\..\\abc.txt", "c:\\test\\abc.txt" },
    { "c:\\test\\123\\..\\..\\abc.txt", "c:\\abc.txt" },
    { "c:\\test\\123\\..\\..\\..\\abc.txt", "abc.txt" },
    { "c:\\test\\123\\..\\.\\..\\abc.txt", "c:\\abc.txt" },
};

class path_resolve : public ::testing::TestWithParam<resolve_path_param> {

};

INSTANTIATE_TEST_SUITE_P(os, path_resolve, testing::ValuesIn(resolve_path_tests));

TEST_P(path_resolve, os) {
    const auto &param = GetParam();
    char output[256];

    memset(output, 'z', sizeof(output));
    mz_path_resolve(param.path, output, sizeof(output));
    EXPECT_STREQ(output, param.expected_path);
}
