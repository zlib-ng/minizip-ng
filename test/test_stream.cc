/* test_stream.cc - Test basic streaming functionality
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"

#include <gtest/gtest.h>

typedef void (*stream_test_cb)(const char *name, int32_t count, const uint8_t *find, int32_t find_size,
    mz_stream_find_cb find_cb);

static void test_stream_find_begin(const char *name, int32_t count, const uint8_t *find, int32_t find_size,
    mz_stream_find_cb find_cb) {
    void *mem_stream = NULL;
    int32_t i = 0;
    int32_t x = 0;
    int64_t last_pos = 0;
    int64_t position = 0;

    MZ_UNUSED(name);

    ASSERT_GT(find_size, 0);
    ASSERT_NE(find, nullptr);
    ASSERT_NE(find_cb, nullptr);

    for (i = 0; i < count; i++) {
        mz_stream_mem_create(&mem_stream);
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE);

        /* Find when the needle is at the beginning of the stream */
        for (x = 0; x < i && x < find_size; x++)
            mz_stream_write_uint8(mem_stream, find[x]);
        while (x++ < i)
            mz_stream_write_uint8(mem_stream, 0);

        if (find_cb == mz_stream_find)
            mz_stream_seek(mem_stream, 0, MZ_SEEK_SET);

        find_cb(mem_stream, (const void *)find, find_size, i, &position);

        /* Should always find at the start of the stream if entire needle
           was written to stream */
        EXPECT_EQ(position, (i < find_size) ? -1 : 0)
            << "name: " << name << std::endl
            << "find_size: " << find_size << std::endl
            << "index: " << i << std::endl;

        mz_stream_seek(mem_stream, 0, MZ_SEEK_END);
        last_pos = mz_stream_tell(mem_stream);
        mz_stream_mem_delete(&mem_stream);

        /* Shouldn't be at the end of the stream */
        EXPECT_NE(position, last_pos);
    }
}

static void test_stream_find_end(const char *name, int32_t count, const uint8_t *find, int32_t find_size,
    mz_stream_find_cb find_cb) {
    void *mem_stream = NULL;
    int32_t i = 0;
    int32_t x = 0;
    int32_t y = 0;
    int64_t last_pos = 0;
    int64_t position = 0;

    MZ_UNUSED(name);

    ASSERT_GT(find_size, 0);
    ASSERT_NE(find, nullptr);
    ASSERT_NE(find_cb, nullptr);

    for (i = 0; i < count; i++) {
        mz_stream_mem_create(&mem_stream);
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE);

        /* Find when the needle is at the end of the stream */
        for (x = 0; x < i - find_size; x++)
            mz_stream_write_uint8(mem_stream, 0);
        for (y = 0; x + y < i && y < find_size; y++)
            mz_stream_write_uint8(mem_stream, find[y]);

        if (find_cb == mz_stream_find)
            mz_stream_seek(mem_stream, 0, MZ_SEEK_SET);

        find_cb(mem_stream, (const void *)find, find_size, i, &position);

        /* Should always find after zeros if entire needle
           was written to stream */
        EXPECT_EQ(position, (i < find_size) ? -1 : (i - find_size))
            << "name: " << name << std::endl
            << "find_size: " << find_size << std::endl
            << "index: " << i << std::endl;

        mz_stream_seek(mem_stream, 0, MZ_SEEK_END);
        last_pos = mz_stream_tell(mem_stream);
        mz_stream_mem_delete(&mem_stream);

        /* Shouldn't be at the end of the stream */
        EXPECT_NE(position, last_pos);
    }
}

static void test_stream_find_middle(const char *name, int32_t count, const uint8_t *find, int32_t find_size,
    mz_stream_find_cb find_cb) {
    void *mem_stream = NULL;
    int32_t i = 0;
    int32_t x = 0;
    int64_t last_pos = 0;
    int64_t position = 0;

    MZ_UNUSED(name);

    ASSERT_GT(find_size, 0);
    ASSERT_NE(find, nullptr);
    ASSERT_NE(find_cb, nullptr);

    for (i = 0; i < count; i++) {
        mz_stream_mem_create(&mem_stream);
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE);

        /* Find when the neddle is in the middle of the stream */
        for (x = 0; x < i; x++)
            mz_stream_write_uint8(mem_stream, 0);
        mz_stream_write(mem_stream, find, find_size);
        for (x = 0; x < i; x++)
            mz_stream_write_uint8(mem_stream, 0);

        if (find_cb == mz_stream_find)
            mz_stream_seek(mem_stream, 0, MZ_SEEK_SET);

        find_cb(mem_stream, (const void *)find, find_size, i + find_size+ i, &position);

        /* Should always find after initial set of zeros */
        EXPECT_EQ(position, i)
            << "name: " << name << std::endl
            << "find_size: " << find_size << std::endl
            << "index: " << i << std::endl;

        mz_stream_seek(mem_stream, 0, MZ_SEEK_END);
        last_pos = mz_stream_tell(mem_stream);
        mz_stream_mem_delete(&mem_stream);

        /* Shouldn't be at the end of the stream */
        EXPECT_NE(position, last_pos);
    }
}

static void test_stream_find_middle_odd(const char *name, int32_t count, const uint8_t *find, int32_t find_size,
    mz_stream_find_cb find_cb) {
    void *mem_stream = NULL;
    int32_t i = 0;
    int32_t x = 0;
    int64_t last_pos = 0;
    int64_t position = 0;

    MZ_UNUSED(name);

    ASSERT_GT(find_size, 0);
    ASSERT_NE(find, nullptr);
    ASSERT_NE(find_cb, nullptr);

    for (i = 0; i < count; i++) {
        mz_stream_mem_create(&mem_stream);
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE);

        /* Find when the needle is in the middle of the stream */
        for (x = 0; x < i; x++)
            mz_stream_write_uint8(mem_stream, 0);
        mz_stream_write(mem_stream, find, find_size);
        for (x = 0; x < i + 1; x++)
            mz_stream_write_uint8(mem_stream, 0);

        if (find_cb == mz_stream_find)
            mz_stream_seek(mem_stream, 0, MZ_SEEK_SET);

        find_cb(mem_stream, (const void *)find, find_size, i + find_size + i + 1, &position);

        /* Should always find after initial set of zeros */
        EXPECT_EQ(position, i)
            << "name: " << name << std::endl
            << "find_size: " << find_size << std::endl
            << "index: " << i << std::endl;

        mz_stream_seek(mem_stream, 0, MZ_SEEK_END);
        last_pos = mz_stream_tell(mem_stream);
        mz_stream_mem_delete(&mem_stream);

        /* Shouldn't be at the end of the stream */
        EXPECT_NE(position, last_pos);
    }
}

struct stream_find_param {
    const char        *name;
    stream_test_cb    test_cb;
    mz_stream_find_cb find_cb;

    friend std::ostream &operator<<(std::ostream &os, const stream_find_param &param) {
        return os << "name: " << param.name;
    }
};

constexpr stream_find_param find_tests[] = {
    { "begin", test_stream_find_begin, mz_stream_find },
    { "begin reverse", test_stream_find_begin, mz_stream_find_reverse },
    { "end", test_stream_find_end, mz_stream_find },
    { "end reverse", test_stream_find_end, mz_stream_find_reverse },
    { "middle", test_stream_find_middle, mz_stream_find },
    { "middle reverse", test_stream_find_middle, mz_stream_find_reverse },
    { "middle odd", test_stream_find_middle_odd, mz_stream_find },
    { "middle odd reverse", test_stream_find_middle_odd, mz_stream_find_reverse }
};

class stream_find : public ::testing::TestWithParam<stream_find_param> {

};

INSTANTIATE_TEST_SUITE_P(stream, stream_find, testing::ValuesIn(find_tests));

TEST_P(stream_find, find) {
    const auto &param = GetParam();
    const char *find = "0123456789";
    int32_t c = 1;

    for (c = 1; c < (int32_t)strlen(find); c += 1)
        param.test_cb(param.name, 2096, (const uint8_t *)find, c, param.find_cb);
}
