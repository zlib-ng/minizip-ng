/* mz_util.h -- Utility functions
   Version 2.6.0, October 8, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_UTIL_H
#define MZ_UTIL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t mz_path_combine(char *path, const char *join, int32_t max_path);
// Combines two paths

int32_t mz_path_compare_wc(const char *path, const char *wildcard, uint8_t ignore_case);
// Compare two paths with wildcard

int32_t mz_path_resolve(const char *path, char *target, int32_t max_target);
// Resolves path

int32_t mz_path_remove_filename(char *path);
// Remove the filename from a path

int32_t mz_path_get_filename(const char *path, const char **filename);
// Get the filename from a path

int32_t mz_dir_make(const char *path);
// Creates a directory recursively

int32_t mz_file_get_crc(const char *path, uint32_t *result_crc);
// Gets the crc32 hash of a file

int32_t mz_encoding_cp437_to_utf8(const char *source, char *target, int32_t max_target);
// Converts ibm cp437 encoded string to utf8

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
