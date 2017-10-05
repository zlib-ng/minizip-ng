/* mzstrm.c -- Stream interface
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Modifications for Zip64 support
     Copyright (C) 2009-2010 Mathias Svensson
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "zip.h"
#include "unzip.h"

#include "mz_compat.h"

#ifndef VERSIONMADEBY
#  define VERSIONMADEBY             (0x0) // platform dependent
#endif

extern zipFile ZEXPORT zipOpen(const char *path, int append, voidpf stream)
{
    return zipOpen2(path, append, NULL, stream);
}

extern zipFile ZEXPORT zipOpen2(const char *path, int append, const char **globalcomment, voidpf stream)
{
    return zipOpen3(path, append, 0, globalcomment, stream);
}

extern zipFile ZEXPORT zipOpen3(const char *path, int append, uint64_t disk_size, const char **globalcomment, voidpf stream)
{
    zipFile file = mz_zip_open(path, append, disk_size, stream);
    if (file != NULL && globalcomment != NULL)
        mz_zip_get_global_comment(file, globalcomment);
    return file;
}

extern int ZEXPORT zipOpenNewFileInZip5(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t compression_method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base, int zip64)
{
    mz_zip_file file_info;

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

    return mz_zip_entry_open(file, &file_info, &compress_info, &crypt_info);
}

extern int ZEXPORT zipOpenNewFileInZip4_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base, int zip64)
{
    return zipOpenNewFileInZip5(file, filename, zipfi, extrafield_local, size_extrafield_local, extrafield_global, size_extrafield_global,
        comment, method, level, raw, windowBits, memLevel, strategy, password, crc_for_crypting, version_madeby, flag_base, zip64);
}

extern int ZEXPORT zipOpenNewFileInZip4(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel,
        strategy, password, crc_for_crypting, version_madeby, flag_base, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel,
        strategy, password, crc_for_crypting, VERSIONMADEBY, 0, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, int zip64)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel, strategy,
        password, crc_for_crypting, VERSIONMADEBY, 0, zip64);
}

extern int ZEXPORT zipWriteInFileInZip(zipFile file, const void *buf, uint32_t len)
{
    return mz_zip_entry_write(file, buf, len);
}

extern int ZEXPORT zipCloseFileInZipRaw(zipFile file, uint32_t uncompressed_size, uint32_t crc32)
{
    return mz_zip_entry_close_raw(file, uncompressed_size, crc32);
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
    return zipClose2_64(file, global_comment, VERSIONMADEBY);
}

extern int ZEXPORT zipClose2_64(zipFile file, const char *global_comment, uint16_t version_madeby)
{
    return mz_zip_close(file, global_comment, version_madeby);
}

extern unzFile ZEXPORT unzOpen(const char *path, void *stream)
{
    return mz_unzip_open(path, stream);
}

extern int ZEXPORT unzClose(unzFile file)
{
    return mz_unzip_close(file);
}

extern int ZEXPORT unzOpenCurrentFile3(unzFile file, int *method, int *level, int raw, const char *password)
{
    if (method != NULL)
        *method = 0;
    if (level != NULL)
        *level = 0;
    return mz_unzip_entry_open(file, raw, password);
}

extern int ZEXPORT unzOpenCurrentFile(void *file)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, NULL);
}

extern int ZEXPORT unzOpenCurrentFilePassword(void *file, const char *password)
{
    return unzOpenCurrentFile3(file, NULL, NULL, 0, password);
}

extern int ZEXPORT unzOpenCurrentFile2(void *file, int *method, int *level, int raw)
{
    return unzOpenCurrentFile3(file, method, level, raw, NULL);
}

extern int ZEXPORT unzGoToFirstFile(void *file)
{
    return mz_unzip_goto_first_entry(file);
}

extern int ZEXPORT unzGoToNextFile(void *file)
{
    return mz_unzip_goto_next_entry(file);
}

/* Read bytes from the current file.
   buf contain buffer where data must be copied
   len the size of buf.

   return the number of byte copied if some bytes are copied
   return 0 if the end of file was reached
   return <0 with error code if there is an error (UNZ_ERRNO for IO error, or zLib error for uncompress error) */

extern int ZEXPORT unzReadCurrentFile(voidpf file, voidp buf, uint32_t len)
{
    return mz_unzip_entry_read(file, buf, len);
}

extern int ZEXPORT unzGetCurrentFileInfo(voidpf file, unz_file_info *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size)
{
    mz_unzip_file *file_info;
    int16_t bytes_to_copy = 0;
    int err = MZ_OK;

    err = mz_unzip_entry_get_info(file, &file_info);

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

extern int ZEXPORT unzGetCurrentFileInfo64(voidpf file, unz_file_info64 * pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size)
{
    mz_unzip_file *file_info;
    int16_t bytes_to_copy = 0;
    int err = MZ_OK;

    err = mz_unzip_entry_get_info(file, &file_info);

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

extern int ZEXPORT unzCloseCurrentFile(unzFile file)
{
    return mz_unzip_entry_close(file);
}

extern int ZEXPORT unzLocateFile(unzFile file, const char *filename, unzFileNameComparer filename_compare_func)
{
    return mz_unzip_locate_entry(file, filename, filename_compare_func);
}

extern int ZEXPORT unzGetGlobalInfo(voidpf file, unz_global_info* pglobal_info32)
{
    unz_global_info64 global_info64;
    int err = unzGetGlobalInfo64(file, &global_info64);
    if (err != UNZ_OK)
    {
        pglobal_info32->number_entry = (uint32_t)global_info64.number_entry;
        pglobal_info32->size_comment = global_info64.size_comment;
        pglobal_info32->number_disk_with_CD = global_info64.number_disk_with_CD;
    }
    return MZ_OK;
}

extern int ZEXPORT unzGetGlobalInfo64(voidpf file, unz_global_info64 *pglobal_info)
{
    mz_unzip_global global_info;
    int err = mz_unzip_get_global_info(file, &global_info);
    if (err == MZ_OK)
    {
        pglobal_info->size_comment = global_info.comment_size;
        pglobal_info->number_entry = global_info.number_entry;
        pglobal_info->number_disk_with_CD = global_info.number_disk_with_CD;
    }
    return err;
}

extern int ZEXPORT unzGetGlobalComment(voidpf file, char *comment, uint16_t comment_size)
{
    return mz_unzip_get_global_comment(file, comment, comment_size);
}
