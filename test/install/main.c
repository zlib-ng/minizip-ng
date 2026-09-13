/* main.c - Test linking against an installed minizip package
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_strm_zstd.h"

int main(void) {
    uint8_t buf[4];
    void *stream = mz_stream_zstd_create();

    if (!stream)
        return 1;
    mz_stream_zstd_delete(&stream);

    if (mz_os_rand(buf, (int32_t)sizeof(buf)) != (int32_t)sizeof(buf))
        return 1;

    return 0;
}
