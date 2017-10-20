/* mz_os_win32.c -- System functions for Windows
   Version 2.1.0, October 20th, 2017
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
#include <direct.h>

#include <windows.h>
#include <wincrypt.h>

#include "mz.h"

#include "mz_os.h"
#include "mz_os_win32.h"

/***************************************************************************/

#if defined(WINAPI_FAMILY_PARTITION) && (!(defined(MZ_USING_WINRT_API)))
#  if !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#    define MZ_USING_WINRT_API 1
#  endif
#endif

/***************************************************************************/

typedef struct DIR_int_s {
    void            *find_handle;
    WIN32_FIND_DATAW find_data;
    struct dirent    entry;
    uint8_t          end;
} DIR_int;

/***************************************************************************/

int32_t mz_win32_rand(uint8_t *buf, int32_t size)
{
    HCRYPTPROV provider;
    unsigned __int64 pentium_tsc[1];
    int32_t len = 0;
    int32_t result = 0;


    if (CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        result = CryptGenRandom(provider, size, buf);
        CryptReleaseContext(provider, 0);
        if (result)
            return size;
    }

    for (len = 0; len < (int)size; len += 1)
    {
        if (len % 8 == 0)
            QueryPerformanceCounter((LARGE_INTEGER *)pentium_tsc);
        buf[len] = ((unsigned char*)pentium_tsc)[len % 8];
    }

    return len;
}

int32_t mz_win32_get_file_date(const char *path, uint32_t *dos_date)
{
    FILETIME ftm_local;
    HANDLE handle = NULL;
    WIN32_FIND_DATAW ff32;
    wchar_t *path_wide = NULL;
    uint32_t path_wide_size = 0;
    int32_t err = MZ_INTERNAL_ERROR;

    path_wide_size = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    path_wide = (wchar_t *)malloc((path_wide_size + 1) * sizeof(wchar_t));
    memset(path_wide, 0, sizeof(wchar_t) * (path_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, path, -1, path_wide, path_wide_size);

    handle = FindFirstFileW(path_wide, &ff32);

    free(path_wide);

    if (handle != INVALID_HANDLE_VALUE)
    {
        FileTimeToLocalFileTime(&(ff32.ftLastWriteTime), &ftm_local);
        FileTimeToDosDateTime(&ftm_local, ((LPWORD)dos_date) + 1, ((LPWORD)dos_date) + 0);
        FindClose(handle);
        err = MZ_OK;
    }

    return err;
}

int32_t mz_win32_set_file_date(const char *path, uint32_t dos_date)
{
    HANDLE handle = NULL;
    FILETIME ftm, ftm_local, ftm_create, ftm_access, ftm_modified;
    wchar_t *path_wide = NULL;
    uint32_t path_wide_size = 0;
    int32_t err = MZ_OK;

    path_wide_size = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    path_wide = (wchar_t *)malloc((path_wide_size + 1) * sizeof(wchar_t));
    memset(path_wide, 0, sizeof(wchar_t) * (path_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, path, -1, path_wide, path_wide_size);

#ifdef MZ_USING_WINRT_API
    handle = CreateFile2W(path_wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#else
    handle = CreateFileW(path_wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif

    free(path_wide);

    if (handle != INVALID_HANDLE_VALUE)
    {
        GetFileTime(handle, &ftm_create, &ftm_access, &ftm_modified);
        DosDateTimeToFileTime((WORD)(dos_date >> 16), (WORD)dos_date, &ftm_local);
        LocalFileTimeToFileTime(&ftm_local, &ftm);

        if (SetFileTime(handle, &ftm, &ftm_access, &ftm) == 0)
            err = MZ_INTERNAL_ERROR;

        CloseHandle(handle);
    }

    return err;
}

int32_t mz_win32_make_dir(const char *path)
{
    wchar_t *path_wide = NULL;
    uint32_t path_wide_size = 0;
    int32_t err = 0;


    path_wide_size = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    path_wide = (wchar_t *)malloc((path_wide_size + 1) * sizeof(wchar_t));
    memset(path_wide, 0, sizeof(wchar_t) * (path_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, path, -1, path_wide, path_wide_size);

    err = _wmkdir(path_wide);

    free(path_wide);

    if (err != 0 && errno != EEXIST)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

DIR *mz_win32_open_dir(const char *path)
{
    WIN32_FIND_DATAW find_data;
    DIR_int *dir_int = NULL;
    wchar_t *path_wide = NULL;
    uint32_t path_wide_size = 0;
    char fixed_path[320];
    void *handle = NULL;


    fixed_path[0] = 0;
    mz_path_combine(fixed_path, path, sizeof(fixed_path));
    mz_path_combine(fixed_path, "*", sizeof(fixed_path));

    path_wide_size = MultiByteToWideChar(CP_UTF8, 0, fixed_path, -1, NULL, 0);
    path_wide = (wchar_t *)malloc((path_wide_size + 1) * sizeof(wchar_t));
    memset(path_wide, 0, sizeof(wchar_t) * (path_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, fixed_path, -1, path_wide, path_wide_size);

    handle = FindFirstFileW(path_wide, &find_data);

    free(path_wide);

    if (handle == INVALID_HANDLE_VALUE)
        return NULL;

    dir_int = (DIR_int *)malloc(sizeof(DIR_int));
    dir_int->find_handle = handle;
    dir_int->end = 0;

    memcpy(&dir_int->find_data, &find_data, sizeof(dir_int->find_data));

    return (DIR *)dir_int;
}

struct dirent* mz_win32_read_dir(DIR *dir)
{
    DIR_int *dir_int;

    if (dir == NULL)
        return NULL;

    dir_int = (DIR_int *)dir;
    if (dir_int->end)
        return NULL;

    WideCharToMultiByte(CP_UTF8, 0, dir_int->find_data.cFileName, -1, 
        dir_int->entry.d_name, sizeof(dir_int->entry.d_name), NULL, NULL);
    
    if (FindNextFileW(dir_int->find_handle, &dir_int->find_data) == 0)
    {
        if (GetLastError() != ERROR_NO_MORE_FILES)
            return NULL;

        dir_int->end = 1;
    }
 
    return &dir_int->entry;
}

int32_t mz_win32_close_dir(DIR *dir)
{
    DIR_int *dir_int;

    if (dir == NULL)
        return MZ_PARAM_ERROR;

    dir_int = (DIR_int *)dir;
    if (dir_int->find_handle != INVALID_HANDLE_VALUE)
        FindClose(dir_int->find_handle);
    free(dir_int);
    return MZ_OK;
}

int32_t mz_win32_is_dir(const char *path)
{
    wchar_t *path_wide = NULL;
    uint32_t path_wide_size = 0;
    int32_t attribs = 0;

    path_wide_size = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
    path_wide = (wchar_t *)malloc((path_wide_size + 1) * sizeof(wchar_t));
    memset(path_wide, 0, sizeof(wchar_t) * (path_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, path, -1, path_wide, path_wide_size);

    attribs = GetFileAttributesW(path_wide);

    free(path_wide);

    if (attribs & FILE_ATTRIBUTE_DIRECTORY)
        return MZ_OK;

    return MZ_EXIST_ERROR;
}