/* mz_os.h -- System functions
   Version 2.6.0, October 8, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_OS_H
#define MZ_OS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#if defined(__APPLE__)
#define MZ_VERSION_MADEBY_HOST_SYSTEM (MZ_HOST_SYSTEM_OSX_DARWIN)
#elif defined(unix)
#define MZ_VERSION_MADEBY_HOST_SYSTEM (MZ_HOST_SYSTEM_UNIX)
#elif defined(_WIN32)
#define MZ_VERSION_MADEBY_HOST_SYSTEM (MZ_HOST_SYSTEM_WINDOWS_NTFS)
#endif

#ifdef HAVE_LZMA
#define MZ_VERSION_MADEBY_ZIP_VERSION (63)
#elif HAVE_AES
#define MZ_VERSION_MADEBY_ZIP_VERSION (51)
#elif HAVE_BZIP2
#define MZ_VERSION_MADEBY_ZIP_VERSION (46)
#else
#define MZ_VERSION_MADEBY_ZIP_VERSION (45)
#endif

#define MZ_VERSION_MADEBY             ((MZ_VERSION_MADEBY_HOST_SYSTEM << 8) | \
                                       (MZ_VERSION_MADEBY_ZIP_VERSION))

/***************************************************************************/

#if defined(_WIN32)
struct dirent {
    char d_name[256];
};
typedef void* DIR;
#endif

/***************************************************************************/

wchar_t *mz_os_unicode_string_create(const char *string);
void     mz_os_unicode_string_delete(wchar_t **string);

int32_t  mz_os_rename(const char *source_path, const char *target_path);
int32_t  mz_os_delete(const char *path);
int32_t  mz_os_file_exists(const char *path);
int64_t  mz_os_get_file_size(const char *path);
int32_t  mz_os_get_file_date(const char *path, time_t *modified_date, time_t *accessed_date, time_t *creation_date);
int32_t  mz_os_set_file_date(const char *path, time_t modified_date, time_t accessed_date, time_t creation_date);
int32_t  mz_os_get_file_attribs(const char *path, uint32_t *attributes);
int32_t  mz_os_set_file_attribs(const char *path, uint32_t attributes);
int32_t  mz_os_make_dir(const char *path);
DIR*     mz_os_open_dir(const char *path);
struct
dirent*  mz_os_read_dir(DIR *dir);
int32_t  mz_os_close_dir(DIR *dir);
int32_t  mz_os_is_dir(const char *path);
uint64_t mz_os_ms_time(void);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
