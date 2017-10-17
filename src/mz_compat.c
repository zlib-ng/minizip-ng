/* mz_compat.c -- Backwards compatible interface for older versions
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mz_error.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_zlib.h"
#include "mz_zip.h"
#include "mz_unzip.h"

#include "mz_compat.h"

/***************************************************************************/

typedef struct mz_compat_s {
    void *stream;
    void *handle;
} mz_compat;

/***************************************************************************/

extern zipFile ZEXPORT zipOpen(const char *path, int append)
{
    return zipOpen2(path, append, NULL, mz_stream_os_get_interface());
}

extern zipFile ZEXPORT zipOpen64(const void *path, int append)
{
    return zipOpen2(path, append, NULL, mz_stream_os_get_interface());
}

extern zipFile ZEXPORT zipOpen2(const char *path, int append, const char **globalcomment,
    zlib_filefunc_def *pzlib_filefunc_def)
{
    return zipOpen2_64(path, append, globalcomment, pzlib_filefunc_def);
}

extern zipFile ZEXPORT zipOpen2_64(const void *path, int append, const char **globalcomment, 
    zlib_filefunc64_def *pzlib_filefunc_def)
{
    mz_compat *compat = NULL;
    int32_t mode = MZ_STREAM_MODE_READWRITE;
    int32_t open_existing = 0;
    int16_t err = MZ_OK;
    void *handle = NULL;
    void *stream = NULL;

    if (mz_stream_create(&stream, (mz_stream_vtbl *)pzlib_filefunc_def) == NULL)
        return NULL;

    switch (append)
    {
    case APPEND_STATUS_CREATE:
        mode |= MZ_STREAM_MODE_CREATE;
        break;
    case APPEND_STATUS_CREATEAFTER:
        mode |= MZ_STREAM_MODE_CREATE | MZ_STREAM_MODE_APPEND;
        break;
    case APPEND_STATUS_ADDINZIP:
        open_existing = 1;
        break;
    }

    if (mz_stream_open(stream, path, mode) != MZ_OK)
    {
        mz_stream_delete(&stream);
        return NULL;
    }

    handle = mz_zip_open(open_existing, stream);

    if (handle == NULL)
    {
        mz_stream_delete(&stream);
        return NULL;
    }

    if (globalcomment != NULL)
        mz_zip_get_global_comment(handle, globalcomment);

    compat = (mz_compat *)malloc(sizeof(mz_compat));
    compat->handle = handle;
    compat->stream = stream;

    return (zipFile)compat;
}

extern int ZEXPORT zipOpenNewFileInZip5(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, 
    int raw, int windowBits, int memLevel, int strategy, const char *password, 
    ZIP_UNUSED uint32_t crc_for_crypting,  uint16_t version_madeby, uint16_t flag_base, int zip64)
{
    mz_compat *compat = (mz_compat *)file;
    mz_zip_file file_info;

    if (compat == NULL)
        return MZ_PARAM_ERROR;

    if (zipfi != NULL)
    {
        file_info.dos_date = zipfi->dos_date;
        file_info.external_fa = zipfi->external_fa;
        file_info.internal_fa = zipfi->internal_fa;
    }

    file_info.filename = filename;
    file_info.extrafield_local = extrafield_local;
    file_info.extrafield_local_size = size_extrafield_local;
    file_info.extrafield_global = extrafield_global;
    file_info.extrafield_global_size = size_extrafield_global;
    file_info.version_madeby = version_madeby;
    file_info.comment = comment;
    file_info.flag = flag_base;
    file_info.zip64 = zip64;

    mz_zip_compress compress_info;

    compress_info.level = level;
    compress_info.window_bits = windowBits;
    compress_info.mem_level = memLevel;
    compress_info.strategy = strategy;
    compress_info.method = compression_method;

    mz_zip_crypt crypt_info;
#ifdef HAVE_AES
    crypt_info.aes = 1;
#endif
    crypt_info.password = password;

    return mz_zip_entry_open(compat->handle, &file_info, &compress_info, &crypt_info);
}

extern int ZEXPORT zipOpenNewFileInZip4_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, 
    int raw, int windowBits, int memLevel,   int strategy, const char *password, 
    ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base, int zip64)
{
    return zipOpenNewFileInZip5(file, filename, zipfi, extrafield_local, size_extrafield_local, 
        extrafield_global, size_extrafield_global, comment, compression_method, level, raw, windowBits, 
        memLevel, strategy, password, crc_for_crypting, version_madeby, flag_base, zip64);
}

extern int ZEXPORT zipOpenNewFileInZip4(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, 
    int raw, int windowBits, int memLevel, int strategy, const char *password, 
    ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, compression_method, level, raw, windowBits, 
        memLevel, strategy, password, crc_for_crypting, version_madeby, flag_base, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, 
    int raw, int windowBits, int memLevel, int strategy, const char *password, 
    ZIP_UNUSED uint32_t crc_for_crypting)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, compression_method, level, raw, windowBits, 
        memLevel, strategy, password, crc_for_crypting, MZ_VERSION_MADEBY, 0, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, 
    int raw, int windowBits, int memLevel, int strategy, const char *password, 
    ZIP_UNUSED uint32_t crc_for_crypting, int zip64)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, compression_method, level, raw, windowBits, 
        memLevel, strategy, password, crc_for_crypting, MZ_VERSION_MADEBY, 0, zip64);
}

extern int ZEXPORT zipWriteInFileInZip(zipFile file, const void *buf, uint32_t len)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_zip_entry_write(compat->handle, buf, len);
}

extern int ZEXPORT zipCloseFileInZipRaw(zipFile file, uint32_t uncompressed_size, uint32_t crc32)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_zip_entry_close_raw(compat->handle, uncompressed_size, crc32);
}

extern int ZEXPORT zipCloseFileInZip(zipFile file)
{
    return zipCloseFileInZipRaw(file, 0, 0);
}

extern int ZEXPORT zipCloseFileInZip64(zipFile file)
{
    return zipCloseFileInZipRaw(file, 0, 0);
}

extern int ZEXPORT zipClose(zipFile file, const char *global_comment)
{
    return zipClose_64(file, global_comment);
}

extern int ZEXPORT zipClose_64(zipFile file, const char *global_comment)
{
    return zipClose2_64(file, global_comment, MZ_VERSION_MADEBY);
}

extern int ZEXPORT zipClose2_64(zipFile file, const char *global_comment, uint16_t version_madeby)
{
    mz_compat *compat = (mz_compat *)file;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;

    err = mz_zip_close(compat->handle, global_comment, version_madeby);

    if (compat->stream != NULL)
        mz_stream_delete(&compat->stream);

    free(compat);

    return err;
}

/***************************************************************************/

extern unzFile ZEXPORT unzOpen(const char *path)
{
    return unzOpen64(path);
}

extern unzFile ZEXPORT unzOpen64(const void *path)
{
    return unzOpen2(path, mz_stream_os_get_interface());
}

extern unzFile ZEXPORT unzOpen2(const char *path, zlib_filefunc_def *pzlib_filefunc_def)
{
    return unzOpen2_64(path, pzlib_filefunc_def);
}

extern unzFile ZEXPORT unzOpen2_64(const void *path, zlib_filefunc64_def *pzlib_filefunc_def)
{
    mz_compat *compat = NULL;
    int32_t mode = MZ_STREAM_MODE_READ;
    int32_t open_existing = 0;
    int16_t err = MZ_OK;
    void *handle = NULL;
    void *stream = NULL;

    if (mz_stream_create(&stream, (mz_stream_vtbl *)pzlib_filefunc_def) == NULL)
        return NULL;
    
    if (mz_stream_open(stream, path, mode) != MZ_OK)
    {
        mz_stream_delete(&stream);
        return NULL;
    }

    handle = mz_unzip_open(stream);

    if (handle == NULL)
    {
        mz_stream_delete(&stream);
        return NULL;
    }

    compat = (mz_compat *)malloc(sizeof(mz_compat));
    compat->handle = handle;
    compat->stream = stream;

    return (unzFile)compat;
}

extern int ZEXPORT unzClose(unzFile file)
{
    mz_compat *compat = (mz_compat *)file;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;

    err = mz_unzip_close(compat->handle);

    if (compat->stream != NULL)
        mz_stream_delete(&compat->stream);

    free(compat);

    return err;
}

extern int ZEXPORT unzGetGlobalInfo(unzFile file, unz_global_info* pglobal_info32)
{
    mz_compat *compat = (mz_compat *)file;
    unz_global_info64 global_info64;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;

    err = unzGetGlobalInfo64(file, &global_info64);
    if (err != UNZ_OK)
    {
        pglobal_info32->number_entry = (uint32_t)global_info64.number_entry;
        pglobal_info32->size_comment = global_info64.size_comment;
        pglobal_info32->number_disk_with_CD = global_info64.number_disk_with_CD;
    }
    return MZ_OK;
}

extern int ZEXPORT unzGetGlobalInfo64(unzFile file, unz_global_info64 *pglobal_info)
{
    mz_compat *compat = (mz_compat *)file;
    mz_unzip_global global_info;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;
    err = mz_unzip_get_global_info(compat->handle, &global_info);
    if (err == MZ_OK)
    {
        pglobal_info->size_comment = global_info.comment_size;
        pglobal_info->number_entry = global_info.number_entry;
        pglobal_info->number_disk_with_CD = global_info.number_disk_with_CD;
    }
    return err;
}

extern int ZEXPORT unzGetGlobalComment(unzFile file, char *comment, uint16_t comment_size)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_get_global_comment(compat->handle, comment, comment_size);
}

extern int ZEXPORT unzOpenCurrentFile3(unzFile file, int *method, int *level, int raw, const char *password)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    if (method != NULL)
        *method = 0;
    if (level != NULL)
        *level = 0;
    return mz_unzip_entry_open(compat->handle, raw, password);
}

extern int ZEXPORT unzOpenCurrentFile(unzFile file)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, NULL);
}

extern int ZEXPORT unzOpenCurrentFilePassword(unzFile file, const char *password)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, password);
}

extern int ZEXPORT unzOpenCurrentFile2(unzFile file, int *method, int *level, int raw)
{
    return unzOpenCurrentFile3(file, method, level, raw, NULL);
}

extern int ZEXPORT unzReadCurrentFile(unzFile file, voidp buf, uint32_t len)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_entry_read(compat->handle, buf, len);
}

extern int ZEXPORT unzCloseCurrentFile(unzFile file)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_entry_close(compat->handle);
}

extern int ZEXPORT unzGetCurrentFileInfo(unzFile file, unz_file_info *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size)
{
    mz_compat *compat = (mz_compat *)file;
    mz_unzip_file *file_info = NULL;
    int16_t bytes_to_copy = 0;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;
    err = mz_unzip_entry_get_info(compat->handle, &file_info);

    if ((err == MZ_OK) && (pfile_info != NULL))
    {
        pfile_info->version = file_info->version;
        pfile_info->version_needed = file_info->version_needed;
        pfile_info->flag = file_info->flag;
        pfile_info->compression_method = file_info->compression_method;
        pfile_info->dos_date = file_info->dos_date;
        pfile_info->crc = file_info->crc;

        pfile_info->size_filename = file_info->filename_size;
        pfile_info->size_file_extra = file_info->extrafield_size;
        pfile_info->size_file_comment = file_info->comment_size;

        pfile_info->disk_num_start = (uint16_t)file_info->disk_num_start;
        pfile_info->internal_fa = file_info->internal_fa;
        pfile_info->external_fa = file_info->external_fa;

        pfile_info->compressed_size = (uint32_t)file_info->compressed_size;
        pfile_info->uncompressed_size = (uint32_t)file_info->uncompressed_size;

        if (filename_size > 0 && filename != NULL)
        {
            bytes_to_copy = filename_size;
            if (bytes_to_copy > file_info->filename_size)
                bytes_to_copy = file_info->filename_size;
            memcpy(filename, file_info->filename, bytes_to_copy);
        }
        if (extrafield_size > 0 && extrafield != NULL)
        {
            bytes_to_copy = extrafield_size;
            if (bytes_to_copy > file_info->extrafield_size)
                bytes_to_copy = file_info->extrafield_size;
            memcpy(extrafield, file_info->extrafield, bytes_to_copy);
        }
        if (comment_size > 0 && comment != NULL)
        {
            bytes_to_copy = comment_size;
            if (bytes_to_copy > file_info->comment_size)
                bytes_to_copy = file_info->comment_size;
            memcpy(comment, file_info->comment, bytes_to_copy);
        }
    }
    return err;
}

extern int ZEXPORT unzGetCurrentFileInfo64(unzFile file, unz_file_info64 * pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size)
{
    mz_compat *compat = (mz_compat *)file;
    mz_unzip_file *file_info = NULL;
    int16_t bytes_to_copy = 0;
    int16_t err = MZ_OK;

    if (compat == NULL)
        return MZ_PARAM_ERROR;

    err = mz_unzip_entry_get_info(compat->handle, &file_info);

    if ((err == MZ_OK) && (pfile_info != NULL))
    {
        pfile_info->version = file_info->version;
        pfile_info->version_needed = file_info->version_needed;
        pfile_info->flag = file_info->flag;
        pfile_info->compression_method = file_info->compression_method;
        pfile_info->dos_date = file_info->dos_date;
        pfile_info->crc = file_info->crc;

        pfile_info->size_filename = file_info->filename_size;
        pfile_info->size_file_extra = file_info->extrafield_size;
        pfile_info->size_file_comment = file_info->comment_size;

        pfile_info->disk_num_start = file_info->disk_num_start;
        pfile_info->internal_fa = file_info->internal_fa;
        pfile_info->external_fa = file_info->external_fa;

        pfile_info->compressed_size = file_info->compressed_size;
        pfile_info->uncompressed_size = file_info->uncompressed_size;

        if (filename_size > 0 && filename != NULL)
        {
            bytes_to_copy = filename_size;
            if (bytes_to_copy > file_info->filename_size)
                bytes_to_copy = file_info->filename_size;
            memcpy(filename, file_info->filename, bytes_to_copy);
        }
        if (extrafield_size > 0 && extrafield != NULL)
        {
            bytes_to_copy = extrafield_size;
            if (bytes_to_copy > file_info->extrafield_size)
                bytes_to_copy = file_info->extrafield_size;
            memcpy(extrafield, file_info->extrafield, bytes_to_copy);
        }
        if (comment_size > 0 && comment != NULL)
        {
            bytes_to_copy = comment_size;
            if (bytes_to_copy > file_info->comment_size)
                bytes_to_copy = file_info->comment_size;
            memcpy(comment, file_info->comment, bytes_to_copy);
        }
    }
    return err;
}

extern int ZEXPORT unzGoToFirstFile(unzFile file)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_goto_first_entry(compat->handle);
}

extern int ZEXPORT unzGoToNextFile(unzFile file)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_goto_next_entry(compat->handle);
}

extern int ZEXPORT unzLocateFile(unzFile file, const char *filename, unzFileNameComparer filename_compare_func)
{
    mz_compat *compat = (mz_compat *)file;
    if (compat == NULL)
        return MZ_PARAM_ERROR;
    return mz_unzip_locate_entry(compat->handle, filename, filename_compare_func);
}

/***************************************************************************/
void fill_fopen_filefunc(zlib_filefunc_def *pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

void fill_fopen64_filefunc(zlib_filefunc64_def *pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

void fill_win32_filefunc(zlib_filefunc_def *pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

void fill_win32_filefunc64(zlib_filefunc64_def *pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

void fill_win32_filefunc64A(zlib_filefunc64_def *pzlib_filefunc_def)
{
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

void fill_win32_filefunc64W(zlib_filefunc64_def *pzlib_filefunc_def)
{
    // NOTE: You should no longer pass in widechar string to open function
    if (pzlib_filefunc_def != NULL)
        pzlib_filefunc_def = mz_stream_os_get_interface();
}

/***************************************************************************/

int get_file_crc(const char *path, void *buf, uint32_t buf_size, uint32_t *result_crc)
{
    void *stream = NULL;
    void *crc32_stream = NULL;
    uint32_t read = 0;
    int16_t err = MZ_OK;

    mz_stream_os_create(&stream);

    err = mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ);

    mz_stream_crc32_create(&crc32_stream);
    mz_stream_crc32_open(crc32_stream, NULL, MZ_STREAM_MODE_READ);

    mz_stream_set_base(crc32_stream, stream);

    if (err == MZ_OK)
    {
        do
        {
            read = mz_stream_crc32_read(crc32_stream, buf, buf_size);

            if ((read < buf_size) && (mz_stream_error(crc32_stream) != MZ_OK))
                err = read;
        }
        while ((err == MZ_OK) && (read > 0));

        mz_stream_os_close(stream);
    }

    mz_stream_crc32_close(crc32_stream);
    *result_crc = mz_stream_crc32_get_value(crc32_stream);
    mz_stream_crc32_delete(&crc32_stream);

    mz_stream_os_delete(&stream);

    return err;
}