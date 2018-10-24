/* mz_os_win32.c -- System functions for Windows
   Version 2.6.0, October 8, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <direct.h>
#include <errno.h>

#include <windows.h>
#if !defined(MZ_ZIP_NO_ENCRYPTION)
#  pragma comment(lib, "crypt32.lib")
#  include <wincrypt.h>
#endif

#include "mz.h"

#include "mz_os.h"
#include "mz_os_win32.h"

/***************************************************************************/

#if defined(WINAPI_FAMILY_PARTITION) && (!(defined(MZ_WINRT_API)))
#  if !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#    define MZ_WINRT_API 1
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

wchar_t *mz_win32_unicode_string_create(const char *string)
{
    wchar_t *string_wide = NULL;
    uint32_t string_wide_size = 0;

    string_wide_size = MultiByteToWideChar(CP_UTF8, 0, string, -1, NULL, 0);
    string_wide = (wchar_t *)MZ_ALLOC((string_wide_size + 1) * sizeof(wchar_t));
    memset(string_wide, 0, sizeof(wchar_t) * (string_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, string, -1, string_wide, string_wide_size);

    return string_wide;
}

void mz_win32_unicode_string_delete(wchar_t **string)
{
    if (string != NULL)
    {
        MZ_FREE(*string);
        *string = NULL;
    }
}

/***************************************************************************/

int32_t mz_win32_rename(const char *source_path, const char *target_path)
{
    wchar_t *source_path_wide = NULL;
    wchar_t *target_path_wide = NULL;
    int32_t result = 0;


    source_path_wide = mz_win32_unicode_string_create(source_path);
    target_path_wide = mz_win32_unicode_string_create(target_path);
    result = MoveFileW(source_path_wide, target_path_wide);
    mz_win32_unicode_string_delete(&source_path_wide);
    mz_win32_unicode_string_delete(&target_path_wide);

    if (result == 0)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_win32_delete(const char *path)
{
    wchar_t *path_wide = NULL;
    int32_t result = 0;


    path_wide = mz_win32_unicode_string_create(path);
    result = DeleteFileW(path_wide);
    mz_win32_unicode_string_delete(&path_wide);

    if (result == 0)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_win32_file_exists(const char *path)
{
    wchar_t *path_wide = NULL;
    DWORD attribs = 0;


    path_wide = mz_win32_unicode_string_create(path);
    attribs = GetFileAttributesW(path_wide);
    mz_win32_unicode_string_delete(&path_wide);

    if (attribs == 0xFFFFFFFF)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int64_t mz_win32_get_file_size(const char *path)
{
    HANDLE handle = NULL;
    LARGE_INTEGER large_size;
    wchar_t *path_wide = NULL;


    path_wide = mz_win32_unicode_string_create(path);
#ifdef MZ_WINRT_API
    handle = CreateFile2W(path_wide, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
    handle = CreateFileW(path_wide, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#endif
    mz_win32_unicode_string_delete(&path_wide);

    large_size.QuadPart = 0;

    if (handle != INVALID_HANDLE_VALUE)
    {
        GetFileSizeEx(handle, &large_size);
        CloseHandle(handle);
    }

    return large_size.QuadPart;
}

static void mz_win32_file_to_unix_time(FILETIME file_time, time_t *unix_time)
{
    uint64_t quad_file_time = 0;
    quad_file_time = file_time.dwLowDateTime;
    quad_file_time |= ((uint64_t)file_time.dwHighDateTime << 32);
    *unix_time = (time_t)((quad_file_time - 116444736000000000LL) / 10000000);
}

static void mz_win32_unix_to_file_time(time_t unix_time, FILETIME *file_time)
{
    uint64_t quad_file_time = 0;
    quad_file_time = ((uint64_t)unix_time * 10000000) + 116444736000000000LL;
    file_time->dwHighDateTime = (quad_file_time >> 32);
    file_time->dwLowDateTime = (uint32_t)(quad_file_time);
}

int32_t mz_win32_get_file_date(const char *path, time_t *modified_date, time_t *accessed_date, time_t *creation_date)
{
    WIN32_FIND_DATAW ff32;
    HANDLE handle = NULL;
    wchar_t *path_wide = NULL;
    int32_t err = MZ_INTERNAL_ERROR;

    path_wide = mz_win32_unicode_string_create(path);
    handle = FindFirstFileW(path_wide, &ff32);
    MZ_FREE(path_wide);

    if (handle != INVALID_HANDLE_VALUE)
    {
        if (modified_date != NULL)
            mz_win32_file_to_unix_time(ff32.ftLastWriteTime, modified_date);
        if (accessed_date != NULL)
            mz_win32_file_to_unix_time(ff32.ftLastAccessTime, accessed_date);
        if (creation_date != NULL)
            mz_win32_file_to_unix_time(ff32.ftCreationTime, creation_date);

        FindClose(handle);
        err = MZ_OK;
    }

    return err;
}

int32_t mz_win32_set_file_date(const char *path, time_t modified_date, time_t accessed_date, time_t creation_date)
{
    HANDLE handle = NULL;
    FILETIME ftm_creation, ftm_accessed, ftm_modified;
    wchar_t *path_wide = NULL;
    int32_t err = MZ_OK;


    path_wide = mz_win32_unicode_string_create(path);
#ifdef MZ_WINRT_API
    handle = CreateFile2W(path_wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#else
    handle = CreateFileW(path_wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
#endif
    mz_win32_unicode_string_delete(&path_wide);

    if (handle != INVALID_HANDLE_VALUE)
    {
        GetFileTime(handle, &ftm_creation, &ftm_accessed, &ftm_modified);

        if (modified_date != 0)
            mz_win32_unix_to_file_time(modified_date, &ftm_modified);
        if (accessed_date != 0)
            mz_win32_unix_to_file_time(accessed_date, &ftm_accessed);
        if (creation_date != 0)
            mz_win32_unix_to_file_time(creation_date, &ftm_creation);

        if (SetFileTime(handle, &ftm_creation, &ftm_accessed, &ftm_modified) == 0)
            err = MZ_INTERNAL_ERROR;

        CloseHandle(handle);
    }

    return err;
}

int32_t mz_win32_get_file_attribs(const char *path, uint32_t *attributes)
{
    wchar_t *path_wide = NULL;
    int32_t err = MZ_OK;

    path_wide = mz_win32_unicode_string_create(path);
    *attributes = GetFileAttributesW(path_wide);
    MZ_FREE(path_wide);

    if (*attributes == INVALID_FILE_ATTRIBUTES)
        err = MZ_INTERNAL_ERROR;

    return err;
}

int32_t mz_win32_set_file_attribs(const char *path, uint32_t attributes)
{
    wchar_t *path_wide = NULL;
    int32_t err = MZ_OK;

    path_wide = mz_win32_unicode_string_create(path);
    if (SetFileAttributesW(path_wide, attributes) == 0)
        err = MZ_INTERNAL_ERROR;
    MZ_FREE(path_wide);

    return err;
}

int32_t mz_win32_make_dir(const char *path)
{
    wchar_t *path_wide = NULL;
    int32_t err = 0;


    path_wide = mz_win32_unicode_string_create(path);
    err = _wmkdir(path_wide);
    mz_win32_unicode_string_delete(&path_wide);

    if (err != 0 && errno != EEXIST)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

DIR *mz_win32_open_dir(const char *path)
{
    WIN32_FIND_DATAW find_data;
    DIR_int *dir_int = NULL;
    wchar_t *path_wide = NULL;
    char fixed_path[320];
    void *handle = NULL;


    fixed_path[0] = 0;
    mz_path_combine(fixed_path, path, sizeof(fixed_path));
    mz_path_combine(fixed_path, "*", sizeof(fixed_path));

    path_wide = mz_win32_unicode_string_create(fixed_path);
    handle = FindFirstFileW(path_wide, &find_data);
    mz_win32_unicode_string_delete(&path_wide);

    if (handle == INVALID_HANDLE_VALUE)
        return NULL;

    dir_int = (DIR_int *)MZ_ALLOC(sizeof(DIR_int));
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
    MZ_FREE(dir_int);
    return MZ_OK;
}

int32_t mz_win32_is_dir(const char *path)
{
    wchar_t *path_wide = NULL;
    uint32_t attribs = 0;

    path_wide = mz_win32_unicode_string_create(path);
    attribs = GetFileAttributesW(path_wide);
    mz_win32_unicode_string_delete(&path_wide);

    if (attribs != 0xFFFFFFFF)
    {
        if (attribs & FILE_ATTRIBUTE_DIRECTORY)
            return MZ_OK;
    }

    return MZ_EXIST_ERROR;
}

uint64_t mz_win32_ms_time(void)
{
    SYSTEMTIME system_time;
    FILETIME file_time;
    uint64_t quad_file_time = 0;

    GetSystemTime(&system_time);
    SystemTimeToFileTime(&system_time, &file_time);

    quad_file_time = file_time.dwLowDateTime;
    quad_file_time |= ((uint64_t)file_time.dwHighDateTime << 32);

    return quad_file_time / 10000 - 11644473600000LL;
}

/***************************************************************************/
#if !defined(MZ_ZIP_NO_ENCRYPTION)
#if !defined(MZ_ZIP_NO_COMPRESSION)
int32_t mz_win32_rand(uint8_t *buf, int32_t size)
{
    HCRYPTPROV provider;
    unsigned __int64 pentium_tsc[1];
    int32_t len = 0;
    int32_t result = 0;


    result = CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (result)
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
#endif

/***************************************************************************/

typedef struct mz_win32_sha_s {
    HCRYPTPROV provider;
    HCRYPTHASH hash;
    int32_t    error;
    uint16_t   algorithm;
} mz_win32_sha;

/***************************************************************************/

void mz_win32_sha_reset(void *handle)
{
    mz_win32_sha *sha = (mz_win32_sha *)handle;
    if (sha->hash)
        CryptDestroyHash(sha->hash);
    sha->hash = 0;
    if (sha->provider)
        CryptReleaseContext(sha->provider, 0);
    sha->provider = 0;
    sha->error = 0;
}

int32_t mz_win32_sha_begin(void *handle)
{
    mz_win32_sha *sha = (mz_win32_sha *)handle;
    ALG_ID alg_id = 0;
    int32_t result = 0;
    int32_t err = MZ_OK;


    if (sha == NULL)
        return MZ_PARAM_ERROR;

    if (sha->algorithm == MZ_HASH_SHA1)
        alg_id = CALG_SHA1;
    else
        alg_id = CALG_SHA_256;

    result = CryptAcquireContext(&sha->provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (!result)
    {
        sha->error = GetLastError();
        err = MZ_CRYPT_ERROR;
    }

    if (result)
    {
        result = CryptCreateHash(sha->provider, alg_id, 0, 0, &sha->hash);
        if (!result)
        {
            sha->error = GetLastError();
            err = MZ_HASH_ERROR;
        }
    }

    return err;
}

int32_t mz_win32_sha_update(void *handle, const void *buf, int32_t size)
{
    mz_win32_sha *sha = (mz_win32_sha *)handle;
    int32_t result = 0;

    if (sha == NULL || buf == NULL)
        return MZ_PARAM_ERROR;
    result = CryptHashData(sha->hash, buf, size, 0);
    if (!result)
    {
        sha->error = GetLastError();
        return MZ_HASH_ERROR;
    }
    return size;
}

int32_t mz_win32_sha_end(void *handle, uint8_t *digest, int32_t digest_size)
{
    mz_win32_sha *sha = (mz_win32_sha *)handle;
    int32_t result = 0;
    int32_t expected_size = 0;

    if (sha == NULL || digest == NULL)
        return MZ_PARAM_ERROR;
    result = CryptGetHashParam(sha->hash, HP_HASHVAL, NULL, &expected_size, 0);
    if (expected_size != digest_size)
        return MZ_BUF_ERROR;
    if (!result)
        return MZ_HASH_ERROR;
    result = CryptGetHashParam(sha->hash, HP_HASHVAL, digest, &digest_size, 0);
    if (!result)
    {
        sha->error = GetLastError();
        return MZ_HASH_ERROR;
    }
    return MZ_OK;
}

void mz_win32_sha_set_algorithm(void *handle, uint16_t algorithm)
{
    mz_win32_sha *sha = (mz_win32_sha *)handle;
    sha->algorithm = algorithm;
}

void *mz_win32_sha_create(void **handle)
{
    mz_win32_sha *sha = NULL;

    sha = (mz_win32_sha *)MZ_ALLOC(sizeof(mz_win32_sha));
    if (sha != NULL)
    {
        memset(sha, 0, sizeof(mz_win32_sha));
        sha->algorithm = MZ_HASH_SHA256;
    }
    if (handle != NULL)
        *handle = sha;

    return sha;
}

void mz_win32_sha_delete(void **handle)
{
    mz_win32_sha *sha = NULL;
    if (handle == NULL)
        return;
    sha = (mz_win32_sha *)*handle;
    if (sha != NULL)
    {
        mz_win32_sha_reset(*handle);
        MZ_FREE(sha);
    }
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_win32_aes_s {
    HCRYPTPROV provider;
    HCRYPTKEY  key;
    int32_t    mode;
    int32_t    error;
    uint16_t   algorithm;
} mz_win32_aes;

/***************************************************************************/

static void mz_win32_aes_free(void *handle)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    if (aes->key)
        CryptDestroyKey(aes->key);
    aes->key = 0;
    if (aes->provider)
        CryptReleaseContext(aes->provider, 0);
    aes->provider = 0;
}

void mz_win32_aes_reset(void *handle)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    mz_win32_aes_free(handle);
}

int32_t mz_win32_aes_encrypt(void *handle, uint8_t *buf, int32_t size, int32_t final)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    int32_t result = 0;
    int32_t buf_len = size;

    if (aes == NULL || buf == NULL)
        return MZ_PARAM_ERROR;
    if (final)
        buf_len = 0;
    result = CryptEncrypt(aes->key, 0, final, 0, buf, &buf_len, size);
    if (!result)
    {
        aes->error = GetLastError();
        return MZ_CRYPT_ERROR;
    }
    return size;
}

int32_t mz_win32_aes_decrypt(void *handle, uint8_t *buf, int32_t size, int32_t final)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    int32_t result = 0;
    if (aes == NULL || buf == NULL)
        return MZ_PARAM_ERROR;
    result = CryptDecrypt(aes->key, 0, final, 0, buf, &size);
    if (!result)
    {
        aes->error = GetLastError();
        return MZ_CRYPT_ERROR;
    }
    return size;
}

int32_t mz_win32_aes_set_key(void *handle, const void *key, int32_t key_length)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    HCRYPTHASH hash = 0;
    ALG_ID alg_id = 0;
    ALG_ID hash_alg_id = 0;
    int32_t result = 0;
    int32_t err = MZ_OK;


    if (aes == NULL || key == NULL)
        return MZ_PARAM_ERROR;
    
    mz_win32_aes_reset(handle);
    
    if (aes->mode == MZ_AES_ENCRYPTION_MODE_128)
        alg_id = CALG_AES_128;
    else if (aes->mode == MZ_AES_ENCRYPTION_MODE_192)
        alg_id = CALG_AES_192;
    else
        alg_id = CALG_AES_256;
    
    if (aes->algorithm == MZ_HASH_SHA1)
        hash_alg_id = CALG_SHA1;
    else
        hash_alg_id = CALG_SHA_256;

    result = CryptAcquireContext(&aes->provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (!result)
    {
        aes->error = GetLastError();
        err = MZ_CRYPT_ERROR;
    }
    if (result)
    {
        result = CryptCreateHash(aes->provider, hash_alg_id, 0, 0, &hash);
        if (!result)
        {
            aes->error = GetLastError();
            err = MZ_HASH_ERROR;
        }
    }
    if (result)
    {
        result = CryptHashData(hash, key, key_length, 0);
        if (!result)
        {
            aes->error = GetLastError();
            err = MZ_HASH_ERROR;
        }
    }
    if (result)
    {
        result = CryptDeriveKey(aes->provider, alg_id, hash, 0, &aes->key);
        if (!result)
        {
            aes->error = GetLastError();
            err = MZ_CRYPT_ERROR;
        }
    }
    if (hash)
        CryptDestroyHash(hash);

    return err;
}

void mz_win32_aes_set_mode(void *handle, int32_t mode)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    aes->mode = mode;
}

void mz_win32_aes_set_algorithm(void *handle, uint16_t algorithm)
{
    mz_win32_aes *aes = (mz_win32_aes *)handle;
    aes->algorithm = algorithm;
}

void *mz_win32_aes_create(void **handle)
{
    mz_win32_aes *aes = NULL;

    aes = (mz_win32_aes *)MZ_ALLOC(sizeof(mz_win32_aes));
    if (aes != NULL)
    {
        aes->algorithm = MZ_HASH_SHA256;
        memset(aes, 0, sizeof(mz_win32_aes));
    }
    if (handle != NULL)
        *handle = aes;

    return aes;
}

void mz_win32_aes_delete(void **handle)
{
    mz_win32_aes *aes = NULL;
    if (handle == NULL)
        return;
    aes = (mz_win32_aes *)*handle;
    if (aes != NULL)
    {
        mz_win32_aes_free(*handle);
        MZ_FREE(aes);
    }
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_win32_hmac_s {
    HCRYPTPROV provider;
    HCRYPTHASH hash;
    HCRYPTKEY  key;
    HMAC_INFO  info;
    int32_t    mode;
    int32_t    error;
    uint16_t   algorithm;
} mz_win32_hmac;

/***************************************************************************/

static void mz_win32_hmac_free(void *handle)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    if (hmac->key)
        CryptDestroyKey(hmac->key);
    hmac->key = 0;
    if (hmac->hash)
        CryptDestroyHash(hmac->hash);
    hmac->hash = 0;
    if (hmac->provider)
        CryptReleaseContext(hmac->provider, 0);
    hmac->provider = 0;
    memset(&hmac->info, 0, sizeof(hmac->info));
}

void mz_win32_hmac_reset(void *handle)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    mz_win32_hmac_free(handle);
}

int32_t mz_win32_hmac_begin(void *handle)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    int32_t result = 0;
    int32_t err = MZ_OK;

    if (hmac == NULL || hmac->provider == 0)
        return MZ_PARAM_ERROR;
    result = CryptCreateHash(hmac->provider, CALG_HMAC, hmac->key, 0, &hmac->hash);
    if (!result)
    {
        hmac->error = GetLastError();
        err = MZ_HASH_ERROR;
    }
    if (result)
    {
        result = CryptSetHashParam(hmac->hash, HP_HMAC_INFO, (uint8_t *)&hmac->info, 0);
        if (!result)
        {
            hmac->error = GetLastError();
            err = MZ_HASH_ERROR;
        }
    }
    return err;
}

int32_t mz_win32_hmac_update(void *handle, const void *buf, int32_t size)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    int32_t result = 0;

    if (hmac == NULL || buf == NULL || hmac->hash == 0)
        return MZ_PARAM_ERROR;

    result = CryptHashData(hmac->hash, buf, size, 0);
    if (!result)
    {
        hmac->error = GetLastError();
        return MZ_HASH_ERROR;
    }
    return MZ_OK;
}

int32_t mz_win32_hmac_end(void *handle, uint8_t *digest, int32_t digest_size)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    int32_t result = 0;
    int32_t expected_size = 0;
    int32_t err = MZ_OK;

    if (hmac == NULL || digest == NULL || hmac->hash == 0)
        return MZ_PARAM_ERROR;
    result = CryptGetHashParam(hmac->hash, HP_HASHVAL, NULL, &expected_size, 0);
    if (expected_size != digest_size)
        return MZ_BUF_ERROR;
    if (!result)
        return MZ_HASH_ERROR;
    result = CryptGetHashParam(hmac->hash, HP_HASHVAL, digest, &digest_size, 0);
    if (!result)
    {
        hmac->error = GetLastError();
        return MZ_HASH_ERROR;
    }
    return MZ_OK;
}

int32_t mz_win32_hmac_set_key(void *handle, const void *key, int32_t key_length)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    HCRYPTHASH hash = 0;
    ALG_ID alg_id = 0;
    typedef struct key_blob_header_s {
	    BLOBHEADER hdr;
	    uint32_t   key_length;
	} key_blob_header_s;
    key_blob_header_s *key_blob_s = NULL;
    uint8_t *key_blob = NULL;
    int32_t key_blob_size = 0;
    int32_t result = 0;
    int32_t err = MZ_OK;


    if (hmac == NULL || key == NULL)
        return MZ_PARAM_ERROR;
    
    mz_win32_hmac_reset(handle);
    
    if (hmac->algorithm == MZ_HASH_SHA1)
        alg_id = CALG_SHA1;
    else
        alg_id = CALG_SHA_256;

    hmac->info.HashAlgid = alg_id;

    result = CryptAcquireContext(&hmac->provider, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
    if (!result)
    {
        hmac->error = GetLastError();
        err = MZ_CRYPT_ERROR;
    }

    key_blob_size = sizeof(key_blob_header_s) + key_length;
    key_blob = (uint8_t *)MZ_ALLOC(key_blob_size);

    key_blob_s = (key_blob_header_s *)key_blob;
    key_blob_s->hdr.bType = PLAINTEXTKEYBLOB;
    key_blob_s->hdr.bVersion = CUR_BLOB_VERSION;
    key_blob_s->hdr.aiKeyAlg = CALG_RC4;
    key_blob_s->hdr.reserved = 0;
    key_blob_s->key_length = key_length;

    memcpy(key_blob + sizeof(key_blob_header_s), key, key_length);

    result = CryptImportKey(hmac->provider, key_blob, key_blob_size, 0, 0, &hmac->key);
    if (!result)
    {
        hmac->error = GetLastError();
        err = MZ_CRYPT_ERROR;
    }

    MZ_FREE(key_blob);

    if (err != MZ_OK)
        mz_win32_hmac_free(handle);

    return err;
}

void mz_win32_hmac_set_algorithm(void *handle, uint16_t algorithm)
{
    mz_win32_hmac *hmac = (mz_win32_hmac *)handle;
    hmac->algorithm = algorithm;
}

void *mz_win32_hmac_create(void **handle)
{
    mz_win32_hmac *hmac = NULL;

    hmac = (mz_win32_hmac *)MZ_ALLOC(sizeof(mz_win32_hmac));
    if (hmac != NULL)
    {
        memset(hmac, 0, sizeof(mz_win32_hmac));
        hmac->algorithm = MZ_HASH_SHA256;
    }
    if (handle != NULL)
        *handle = hmac;

    return hmac;
}

void mz_win32_hmac_delete(void **handle)
{
    mz_win32_hmac *hmac = NULL;
    if (handle == NULL)
        return;
    hmac = (mz_win32_hmac *)*handle;
    if (hmac != NULL)
    {
        mz_win32_hmac_free(*handle);
        MZ_FREE(hmac);
    }
    *handle = NULL;
}

/***************************************************************************/

#if !defined(MZ_ZIP_NO_COMPRESSION)
int32_t mz_win32_sign(uint8_t *message, int32_t message_size, const char *cert_path, const char *cert_pwd,
    const char *timestamp_url, uint8_t **signature, int32_t *signature_size)
{
    CRYPT_SIGN_MESSAGE_PARA sign_params;
    CRYPT_DATA_BLOB cert_data_blob;
    PCCERT_CONTEXT cert_context = NULL;
    CRYPT_TIMESTAMP_CONTEXT *ts_context = NULL;
    CRYPT_ATTR_BLOB crypt_blob;
    CRYPT_ATTRIBUTE unauth_attribs[1];
    HCERTSTORE cert_store = 0;
    void *cert_stream = NULL;
    wchar_t *password_wide = NULL;
    wchar_t *timestamp_url_wide = NULL;
    int32_t result = 0;
    int32_t err = MZ_OK;
    int32_t cert_size = 0;
    uint8_t *cert_data = NULL;
    uint32_t key_spec = 0;
    uint32_t messages_sizes[1];
    uint8_t *messages[1];


    if (message == NULL || cert_path == NULL || signature == NULL || signature_size == NULL)
        return MZ_PARAM_ERROR;
    
    cert_size = (int32_t)mz_os_get_file_size(cert_path);
    if (cert_size == 0)
        return MZ_PARAM_ERROR;

    cert_data = (uint8_t *)MZ_ALLOC(cert_size);

    mz_stream_os_create(&cert_stream);
    err = mz_stream_os_open(cert_stream, cert_path, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
    {
        if (mz_stream_os_read(cert_stream, cert_data, cert_size) != cert_size)
            err = MM_STREAM_ERROR;
        mz_stream_os_close(cert_stream);
    }
    mz_stream_os_delete(&cert_stream);

    cert_data_blob.pbData = cert_data;
    cert_data_blob.cbData = cert_size;

    if ((err == MZ_OK) && (cert_pwd != NULL))
    {
        password_wide = mz_win32_unicode_string_create(cert_pwd);
        cert_store = PFXImportCertStore(&cert_data_blob, password_wide, 0);
        mz_win32_unicode_string_delete(&password_wide);
    }

    if (cert_store == NULL)
        cert_store = PFXImportCertStore(&cert_data_blob, L"", 0);
    if (cert_store == NULL)
        cert_store = PFXImportCertStore(&cert_data_blob, NULL, 0);
    if (cert_store == NULL)
        err = MZ_PARAM_ERROR;

    MZ_FREE(cert_data);

    if (err == MZ_OK)
    {
        cert_context = CertFindCertificateInStore(cert_store,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_HAS_PRIVATE_KEY, NULL, NULL);
        if (cert_context == NULL)
            err = MZ_PARAM_ERROR;
    }
    if (err == MZ_OK)
    {
        memset(&sign_params, 0, sizeof(sign_params));

        sign_params.cbSize = sizeof(sign_params);
        sign_params.dwMsgEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
        sign_params.pSigningCert = cert_context;
        sign_params.HashAlgorithm.pszObjId = szOID_NIST_sha256;
        sign_params.cMsgCert = 1;
        sign_params.rgpMsgCert = &cert_context;

        messages[0] = message;
        messages_sizes[0] = message_size;

        if (timestamp_url != NULL)
            timestamp_url_wide = mz_win32_unicode_string_create(timestamp_url);
        if (timestamp_url_wide != NULL)
        {
            result = CryptRetrieveTimeStamp(timestamp_url_wide, 
                TIMESTAMP_NO_AUTH_RETRIEVAL | TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, 0, szOID_NIST_sha256, 
                NULL, message, message_size, &ts_context, NULL, NULL);

            mz_win32_unicode_string_delete(&timestamp_url_wide);

            if ((result) && (ts_context != NULL))
            {
                crypt_blob.cbData = ts_context->cbEncoded;
                crypt_blob.pbData = ts_context->pbEncoded;

                unauth_attribs[0].pszObjId = "1.2.840.113549.1.9.16.2.14"; //id-smime-aa-timeStampToken
                unauth_attribs[0].cValue = 1;
                unauth_attribs[0].rgValue = &crypt_blob;

                sign_params.rgUnauthAttr = &unauth_attribs[0];
                sign_params.cUnauthAttr = 1;
            }
        }

        if (result)
            result = CryptSignMessage(&sign_params, FALSE, 1, messages, messages_sizes,
                NULL, signature_size);

        if (result && *signature_size > 0)
            *signature = (uint8_t *)MZ_ALLOC(*signature_size);

        if (result && *signature != NULL)
            result = CryptSignMessage(&sign_params, FALSE, 1, messages, messages_sizes,
                *signature, signature_size);

        if (!result)
            err = MZ_CRYPT_ERROR;

        if (ts_context != NULL)
            CryptMemFree(ts_context);
    }

    if (cert_context != NULL)
        CertFreeCertificateContext(cert_context);
    if (cert_store != NULL)
        CertCloseStore(cert_store, 0);

    return err;
}
#endif

int32_t mz_win32_sign_verify(uint8_t *message, int32_t message_size, uint8_t *signature, int32_t signature_size)
{
    CRYPT_VERIFY_MESSAGE_PARA verify_params;
    CRYPT_TIMESTAMP_CONTEXT *crypt_context = NULL;
    PCRYPT_ATTRIBUTES unauth_attribs = NULL;
    HCRYPTMSG crypt_msg = 0;
    HCRYPTMSG ts_msg = 0;
    int32_t result = 0;
    int32_t err = MZ_CRYPT_ERROR;
    uint8_t *decoded = NULL;
    int32_t decoded_size = 0;
    uint8_t *ts_content = NULL;
    int32_t ts_content_size = 0;
    uint8_t *ts_signature = NULL;
    int32_t ts_signature_size = 0;


    memset(&verify_params, 0, sizeof(verify_params));

    verify_params.cbSize = sizeof(verify_params);

    verify_params.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
    verify_params.hCryptProv = 0;
    verify_params.pfnGetSignerCertificate = NULL;
    verify_params.pvGetArg = NULL;
    
    result = CryptVerifyMessageSignature(&verify_params, 0, signature, signature_size,
        NULL, &decoded_size, NULL);

    if (result && decoded_size > 0)
        decoded = (uint8_t *)MZ_ALLOC(decoded_size);

    if (result)
        result = CryptVerifyMessageSignature(&verify_params, 0, signature, signature_size,
            decoded, &decoded_size, NULL);

    crypt_msg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING, 0, 0, 0, NULL, NULL);
    if (crypt_msg != NULL)
    {
        result = CryptMsgUpdate(crypt_msg, signature, signature_size, 1);

        if (result)
            CryptMsgGetParam(crypt_msg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, NULL, &ts_signature_size);

        if ((result) && (ts_signature_size > 0))
            ts_signature = (uint8_t *)MZ_ALLOC(ts_signature_size);

        if ((result) && (ts_signature != NULL))
        {
            result = CryptMsgGetParam(crypt_msg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, ts_signature,
                &ts_signature_size);
            if (result)
            {
                unauth_attribs = (PCRYPT_ATTRIBUTES)ts_signature;

                if ((unauth_attribs->cAttr > 0) && (unauth_attribs->rgAttr[0].cValue > 0))
                {
                    ts_content = unauth_attribs->rgAttr[0].rgValue->pbData;
                    ts_content_size = unauth_attribs->rgAttr[0].rgValue->cbData;
                }
            }

            if ((result) && (ts_content != NULL))
                result = CryptVerifyTimeStampSignature(ts_content, ts_content_size, decoded,
                    decoded_size, 0, &crypt_context, NULL, NULL);

            if (result)
                err = MZ_OK;
        }

        if (ts_signature != NULL)
            MZ_FREE(ts_signature);

        if (crypt_context != NULL)
            CryptMemFree(crypt_context);
    }

    if ((crypt_msg != NULL) && (result) && (decoded_size == signature_size))
    {
        if (memcmp(decoded, signature, signature_size) == 0)
            err = MZ_OK;
    }

    if (decoded != NULL)
        MZ_FREE(decoded);

    if (crypt_msg != NULL)
        CryptMsgClose(crypt_msg);

    return err;
}
#endif