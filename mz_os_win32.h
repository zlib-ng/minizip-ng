/* mz_os_win32.h -- System functions for Windows
   Version 2.6.0, October 8, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_OS_WIN32_H
#define MZ_OS_WIN32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#define MZ_VERSION_MADEBY_HOST_SYSTEM   (MZ_HOST_SYSTEM_WINDOWS_NTFS)

/***************************************************************************/

struct dirent {
    char d_name[256];
};
typedef void* DIR;

/***************************************************************************/

wchar_t *mz_win32_unicode_string_create(const char *string);
void     mz_win32_unicode_string_delete(wchar_t **string);

int32_t  mz_win32_rename(const char *source_path, const char *target_path);
int32_t  mz_win32_delete(const char *path);
int32_t  mz_win32_file_exists(const char *path);
int64_t  mz_win32_get_file_size(const char *path);
int32_t  mz_win32_get_file_date(const char *path, time_t *modified_date, time_t *accessed_date, time_t *creation_date);
int32_t  mz_win32_set_file_date(const char *path, time_t modified_date, time_t accessed_date, time_t creation_date);
int32_t  mz_win32_get_file_attribs(const char *path, uint32_t *attributes);
int32_t  mz_win32_set_file_attribs(const char *path, uint32_t attributes);
int32_t  mz_win32_make_dir(const char *path);
DIR*     mz_win32_open_dir(const char *path);
struct
dirent*  mz_win32_read_dir(DIR *dir);
int32_t  mz_win32_close_dir(DIR *dir);
int32_t  mz_win32_is_dir(const char *path);
uint64_t mz_win32_ms_time(void);

int32_t  mz_win32_rand(uint8_t *buf, int32_t size);
int32_t  mz_win32_sign(uint8_t *message, int32_t message_size, const char *cert_path, const char *cert_pwd, 
                       const char *timestamp_url, uint8_t **signature, int32_t *signature_size);
int32_t  mz_win32_sign_verify(uint8_t *message, int32_t message_size, uint8_t *signature, int32_t signature_size);

/***************************************************************************/

#define mz_os_rename            mz_win32_rename
#define mz_os_delete            mz_win32_delete
#define mz_os_file_exists       mz_win32_file_exists
#define mz_os_get_file_size     mz_win32_get_file_size
#define mz_os_get_file_date     mz_win32_get_file_date
#define mz_os_set_file_date     mz_win32_set_file_date
#define mz_os_get_file_attribs  mz_win32_get_file_attribs
#define mz_os_set_file_attribs  mz_win32_set_file_attribs
#define mz_os_make_dir          mz_win32_make_dir
#define mz_os_open_dir          mz_win32_open_dir
#define mz_os_read_dir          mz_win32_read_dir
#define mz_os_close_dir         mz_win32_close_dir
#define mz_os_is_dir            mz_win32_is_dir
#define mz_os_ms_time           mz_win32_ms_time

#define mz_os_rand              mz_win32_rand
#define mz_os_sign              mz_win32_sign
#define mz_os_sign_verify       mz_win32_sign_verify

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
