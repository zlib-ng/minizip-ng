/* mz_os.h -- System functions
   Version 2.2.1, October 23rd, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_OS_H
#define _MZ_OS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#if !defined(_WIN32) && !defined(USEWIN32IOAPI)
#include "mz_os_posix.h"
#include "mz_strm_posix.h"
#else
#include "mz_os_win32.h"
#include "mz_strm_win32.h"
#endif

/***************************************************************************/

int32_t  mz_file_exists(const char *path);
// Checks to see if a file exists

int64_t  mz_file_get_size(const char *path);
// Gets the size of a file

int32_t  mz_make_dir(const char *path);
// Creates a directory recursively

int32_t  mz_path_combine(char *path, const char *join, int32_t max_path);
// Combines two paths

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
