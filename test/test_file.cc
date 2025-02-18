/* test_file.cc - Test file functionality
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"

#include <gtest/gtest.h>
#include <fstream>
#include <cstdio>

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
