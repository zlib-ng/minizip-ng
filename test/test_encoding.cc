/* test_encoding.cc - Test string encoding
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"

#include <gtest/gtest.h>

TEST(os, utf8_unicode_string) {
    const char *test_string = "Heiz�lr�cksto�abd�mpfung";
    uint8_t *utf8_string = mz_os_utf8_string_create(test_string, MZ_ENCODING_CODEPAGE_950);
    ASSERT_NE(utf8_string, nullptr);
#if defined(_WIN32)
    wchar_t *unicode_string = mz_os_unicode_string_create((const char *)utf8_string, MZ_ENCODING_UTF8);
    ASSERT_NE(unicode_string, nullptr);
    mz_os_unicode_string_delete(&unicode_string);
#endif
    mz_os_utf8_string_delete(&utf8_string);
}
