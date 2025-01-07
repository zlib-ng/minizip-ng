/* test_path.cc - Test path functionality
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
    
    const std::string mainStreamName = "minizip_ads_test";
    const std::string adsName = mainStreamName + ":ads";
    const std::string adsContents = "Alternate Data Stream";
  
    // Create main stream
    std::ofstream mainStream(mainStreamName);
    mainStream.close();

    // Attach ADS
    std::ofstream ads(adsName);
    ads << adsContents;
    ads.close();

    // Get file date
    time_t modified_date = 0;
    time_t accessed_date = 0;
    time_t creation_date = 0;

    EXPECT_EQ(MZ_OK, mz_os_get_file_date(adsName.c_str(), &modified_date, &accessed_date, &creation_date));

    std::remove(mainStreamName.c_str());

    ASSERT_GT(modified_date, 0);
    ASSERT_GT(accessed_date, 0);
    ASSERT_GT(creation_date, 0);
}
