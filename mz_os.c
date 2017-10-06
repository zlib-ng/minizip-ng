/* mz_os.c -- System functions
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <time.h>

#include "mz_error.h"
#include "mz_strm.h"

#include "mz_os.h"

/***************************************************************************/

int32_t mz_os_file_exists(const char *path)
{
    void *stream = NULL;
    int opened = 0;

    mz_stream_os_create(&stream);

    if (mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ) == MZ_OK)
    {
        mz_stream_os_close(stream);
        opened = 1;
    }

    mz_stream_os_delete(&stream);

    return opened;
}

int64_t mz_os_file_get_size(const char *path)
{
    void *stream = NULL;
    int64_t size = 0;
    
    mz_stream_os_create(&stream);

    if (mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ) == MZ_OK)
    {
        mz_stream_os_seek(stream, 0, MZ_STREAM_SEEK_END);
        size = mz_stream_os_tell(stream);
        mz_stream_os_close(stream);
    }

    mz_stream_os_delete(&stream);

    return size;
}

/***************************************************************************/

int mz_invalid_date(const struct tm *ptm)
{
#define datevalue_in_range(min, max, value) ((min) <= (value) && (value) <= (max))
    return (!datevalue_in_range(0, 207, ptm->tm_year) ||
            !datevalue_in_range(0, 11, ptm->tm_mon) ||
            !datevalue_in_range(1, 31, ptm->tm_mday) ||
            !datevalue_in_range(0, 23, ptm->tm_hour) ||
            !datevalue_in_range(0, 59, ptm->tm_min) ||
            !datevalue_in_range(0, 59, ptm->tm_sec));
#undef datevalue_in_range
}

// Conversion without validation
void mz_dosdate_to_raw_tm(uint64_t dos_date, struct tm *ptm)
{
    uint64_t date = (uint64_t)(dos_date >> 16);

    ptm->tm_mday = (uint16_t)(date & 0x1f);
    ptm->tm_mon = (uint16_t)(((date & 0x1E0) / 0x20) - 1);
    ptm->tm_year = (uint16_t)(((date & 0x0FE00) / 0x0200) + 80);
    ptm->tm_hour = (uint16_t)((dos_date & 0xF800) / 0x800);
    ptm->tm_min = (uint16_t)((dos_date & 0x7E0) / 0x20);
    ptm->tm_sec = (uint16_t)(2 * (dos_date & 0x1f));
    ptm->tm_isdst = -1;
}

int32_t mz_dosdate_to_tm(uint64_t dos_date, struct tm *ptm)
{
    mz_dosdate_to_raw_tm(dos_date, ptm);

    if (mz_invalid_date(ptm))
    {
        // Invalid date stored, so don't return it.
        memset(ptm, 0, sizeof(struct tm));
        return -1;
    }
    return 0;
}

time_t mz_dosdate_to_time_t(uint64_t dos_date)
{
    struct tm ptm;
    mz_dosdate_to_raw_tm(dos_date, &ptm);
    return mktime(&ptm);
}

uint32_t mz_tm_to_dosdate(const struct tm *ptm)
{
    struct tm fixed_tm = { 0 };

    // Years supported:
    // [00, 79]      (assumed to be between 2000 and 2079)
    // [80, 207]     (assumed to be between 1980 and 2107, typical output of old
    //                software that does 'year-1900' to get a double digit year)
    // [1980, 2107]  (due to the date format limitations, only years between 1980 and 2107 can be stored.)

    memcpy(&fixed_tm, ptm, sizeof(struct tm));
    if (fixed_tm.tm_year >= 1980) // range [1980, 2107]
        fixed_tm.tm_year -= 1980;
    else if (fixed_tm.tm_year >= 80) // range [80, 99] 
        fixed_tm.tm_year -= 80;
    else // range [00, 79]
        fixed_tm.tm_year += 20;

    if (mz_invalid_date(ptm))
        return 0;

    return (uint32_t)(((fixed_tm.tm_mday) + (32 * (fixed_tm.tm_mon + 1)) + (512 * fixed_tm.tm_year)) << 16) |
        ((fixed_tm.tm_sec / 2) + (32 * fixed_tm.tm_min) + (2048 * (uint32_t)fixed_tm.tm_hour));
}
