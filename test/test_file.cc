/* test_file.cc - Test file functionality
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm_os.h"

#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>

#if !defined(_WIN32) && defined(HAVE_SYMLINK)
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#if GTEST_OS_WINDOWS
TEST(os, get_file_date_ads) {
    const std::string main_stream_name = "minizip_ads_test";
    const std::string ads_name = main_stream_name + ":ads";
    const std::string ads_contents = "Alternate Data Stream";

    // Create main stream
    std::ofstream main_stream(main_stream_name);
    main_stream.close();

    // Attach ADS
    std::ofstream ads(ads_name);
    ads << ads_contents;
    ads.close();

    // Get file date
    time_t modified_date = 0;
    time_t accessed_date = 0;
    time_t creation_date = 0;

    EXPECT_EQ(MZ_OK, mz_os_get_file_date(ads_name.c_str(), &modified_date, &accessed_date, &creation_date));

    std::remove(main_stream_name.c_str());

    ASSERT_GT(modified_date, 0);
    ASSERT_GT(accessed_date, 0);
    ASSERT_GT(creation_date, 0);
}
#endif

#if !defined(_WIN32) && defined(HAVE_SYMLINK)
TEST(path_security, rejects_final_symlink_on_safe_open) {
    char temp_path[] = "/tmp/minizip-open-test-XXXXXX";
    char *root = mkdtemp(temp_path);
    ASSERT_NE(root, nullptr);

    std::string destination = std::string(root) + "/dest";
    std::string outside = std::string(root) + "/outside";
    std::string link = destination + "/victim";

    ASSERT_EQ(mkdir(destination.c_str(), 0755), 0);
    ASSERT_EQ(mkdir(outside.c_str(), 0755), 0);
    ASSERT_EQ(symlink("../outside/victim", link.c_str()), 0);

    void *stream = mz_stream_os_create();
    ASSERT_NE(stream, nullptr);
    EXPECT_NE(mz_stream_os_open(stream, link.c_str(), MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_NOFOLLOW), MZ_OK);
    mz_stream_os_delete(&stream);

    unlink(link.c_str());
    rmdir(outside.c_str());
    rmdir(destination.c_str());
    rmdir(root);
}

TEST(path_security, rejects_empty_safe_open_path) {
    void *stream = mz_stream_os_create();
    ASSERT_NE(stream, nullptr);
    EXPECT_EQ(mz_stream_os_open(stream, "", MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_NOFOLLOW), MZ_PARAM_ERROR);
    mz_stream_os_delete(&stream);
}
#endif
