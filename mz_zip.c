/* zip.c -- Zip manipulation
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2010-2017 Nathan Moinvaziri
     Modifications for AES, PKWARE disk spanning
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "zlib.h"

#include "mz_error.h"
#include "mz_strm.h"
#ifdef HAVE_AES
#  include "mz_strm_aes.h"
#endif
#ifdef HAVE_BZIP2
#  include "mz_strm_bzip.h"
#endif
#ifndef NOCRYPT
#  include "mz_strm_crypt.h"
#endif
#ifdef HAVE_LZMA
#  include "mz_strm_lzma.h"
#endif
#include "mz_strm_mem.h"
#include "mz_strm_zlib.h"

#include "mz_zip.h"

/***************************************************************************/

#define DISKHEADERMAGIC             (0x08074b50)
#define LOCALHEADERMAGIC            (0x04034b50)
#define CENTRALHEADERMAGIC          (0x02014b50)
#define ENDHEADERMAGIC              (0x06054b50)
#define ZIP64ENDHEADERMAGIC         (0x06064b50)
#define ZIP64ENDLOCHEADERMAGIC      (0x07064b50)
#define DATADESCRIPTORMAGIC         (0x08074b50)

#define SIZECENTRALHEADER           (0x2e) // 46
#define SIZECENTRALHEADERLOCATOR    (0x14) // 20
#define SIZECENTRALDIRITEM          (0x2e)
#define SIZEZIPLOCALHEADER          (0x1e)

#ifndef BUFREADCOMMENT
#  define BUFREADCOMMENT            (0x400)
#endif

/***************************************************************************/

typedef struct mz_zip_s
{
    mz_zip_file file_info;
    mz_zip_crypt crypt_info;
    mz_zip_compress compress_info;

    void *stream;                   // main stream
    void *cd_stream;                // memory stream for central directory
    void *compress_stream;          // compression stream
    void *crc32_stream;             // crc32 stream
    void *crypt_stream;             // encryption stream

    uint64_t pos_local_header;      // offset of the local header of the file currently writing
    uint64_t add_position_when_writting_offset;
    uint64_t number_entry;
    uint16_t entry_opened;          // 1 if a file in the zip is currently writ.
    uint64_t disk_size;             // size of each disk
    uint32_t number_disk;           // number of the current disk, used for spanning ZIP
    uint32_t number_disk_with_CD;   // number the the disk with central dir, used for spanning ZIP
#ifndef NO_ADDFILEINEXISTINGZIP
    char *comment;
#endif
} mz_zip;

/***************************************************************************/

// Locate the central directory of a zip file (at the end, just before the global comment)
static uint64_t mz_zip_search_cd(void *stream)
{
    uint8_t buf[BUFREADCOMMENT + 4];
    uint64_t file_size = 0;
    uint64_t back_read = 4;
    uint64_t max_back = UINT16_MAX; // maximum size of global comment
    uint64_t pos_found = 0;
    uint32_t read_size = 0;
    uint64_t read_pos = 0;
    uint32_t i = 0;
    
    if (mz_stream_seek(stream, 0, MZ_STREAM_SEEK_END) != MZ_OK)
        return 0;

    file_size = mz_stream_tell(stream);

    if (max_back > file_size)
        max_back = file_size;

    while (back_read < max_back)
    {
        if (back_read + BUFREADCOMMENT > max_back)
            back_read = max_back;
        else
            back_read += BUFREADCOMMENT;

        read_pos = file_size-back_read;
        read_size = ((BUFREADCOMMENT + 4) < (file_size - read_pos)) ?
                     (BUFREADCOMMENT + 4) : (uint32_t)(file_size - read_pos);

        if (mz_stream_seek(stream, read_pos, MZ_STREAM_SEEK_SET) != MZ_OK)
            break;
        if (mz_stream_read(stream, buf, read_size) != read_size)
            break;

        for (i = read_size - 3; (i--) > 0;)
        {
            if ((*(buf + i)) == (ENDHEADERMAGIC & 0xff) &&
                (*(buf + i + 1)) == (ENDHEADERMAGIC >> 8 & 0xff) &&
                (*(buf + i + 2)) == (ENDHEADERMAGIC >> 16 & 0xff) &&
                (*(buf + i + 3)) == (ENDHEADERMAGIC >> 24 & 0xff))
            {
                pos_found = read_pos + i;
                break;
            }
        }

        if (pos_found != 0)
            break;
    }

    return pos_found;
}

// Locate the central directory 64 of a zip file (at the end, just before the global comment)
static uint64_t mz_zip_search_zip64_cd(void *stream, const uint64_t endcentraloffset)
{
    uint64_t offset = 0;
    uint32_t value32 = 0;

    // Zip64 end of central directory locator
    if (mz_stream_seek(stream, endcentraloffset - SIZECENTRALHEADERLOCATOR, MZ_STREAM_SEEK_SET) != MZ_OK)
        return 0;

    // Read locator signature
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    if (value32 != ZIP64ENDLOCHEADERMAGIC)
        return 0;
    // Number of the disk with the start of the zip64 end of  central directory
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    // Relative offset of the zip64 end of central directory record
    if (mz_stream_read_uint64(stream, &offset) != MZ_OK)
        return 0;
    // Total number of disks
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    // Goto end of central directory record
    if (mz_stream_seek(stream, offset, MZ_STREAM_SEEK_SET) != 0)
        return 0;
    // The signature
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    if (value32 != ZIP64ENDHEADERMAGIC)
        return 0;

    return offset;
}

extern void* ZEXPORT mz_zip_open(uint8_t open_existing, uint64_t disk_size, void *stream)
{
    mz_zip *zip = NULL;
#ifndef NO_ADDFILEINEXISTINGZIP
    uint64_t byte_before_the_zipfile = 0;   // byte before the zip file, (>0 for sfx)
    uint64_t size_central_dir = 0;          // size of the central directory
    uint64_t offset_central_dir = 0;        // offset of start of central directory
    uint64_t number_entry_CD = 0;           // total number of entries in the central dir
    uint64_t number_entry = 0;
    uint64_t central_pos = 0;
    uint16_t value16 = 0;
    uint32_t value32 = 0;
    uint64_t value64 = 0;
    uint16_t comment_size = 0;
#endif
    int16_t err = MZ_OK;


    
    zip = (mz_zip*)malloc(sizeof(mz_zip));
    if (zip == NULL)
        return NULL;

    memset(zip, 0, sizeof(mz_zip));

    zip->stream = stream;
    zip->disk_size = disk_size;

    mz_stream_mem_create(&zip->cd_stream);
    mz_stream_mem_set_grow(zip->cd_stream, 1);
    mz_stream_mem_open(zip->cd_stream, NULL, MZ_STREAM_MODE_CREATE);

#ifndef NO_ADDFILEINEXISTINGZIP
    // Add file in a zip file
    if (open_existing)
    {
        // Read and cache central directory records
        central_pos = mz_zip_search_cd(zip->stream);

        // Disable to allow appending to empty ZIP archive (must be standard zip, not zip64)
        //    if (central_pos == 0)
        //        err = MZ_FORMAT_ERROR;

        if (err == MZ_OK)
        {
            // Read end of central directory info
            if (mz_stream_seek(zip->stream, central_pos, MZ_STREAM_SEEK_SET) != MZ_OK)
                err = MZ_STREAM_ERROR;

            // The signature, already checked
            if (mz_stream_read_uint32(zip->stream, &value32) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Number of this disk
            if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            zip->number_disk = value16;
            // Number of the disk with the start of the central directory
            if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            zip->number_disk_with_CD = value16;
            // Total number of entries in the central dir on this disk
            number_entry = 0;
            if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            else
                number_entry = value16;
            // Total number of entries in the central dir
            number_entry_CD = 0;
            if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            else
                number_entry_CD = value16;
            if (number_entry_CD != number_entry)
                err = MZ_FORMAT_ERROR;
            // Size of the central directory
            size_central_dir = 0;
            if (mz_stream_read_uint32(zip->stream, &value32) != MZ_OK)
                err = MZ_STREAM_ERROR;
            else
                size_central_dir = value32;
            // Offset of start of central directory with respect to the starting disk number
            offset_central_dir = 0;
            if (mz_stream_read_uint32(zip->stream, &value32) != MZ_OK)
                err = MZ_STREAM_ERROR;
            else
                offset_central_dir = value32;
            // Zipfile global comment length
            if (mz_stream_read_uint16(zip->stream, &comment_size) != MZ_OK)
                err = MZ_STREAM_ERROR;

            if ((err == MZ_OK) && ((number_entry_CD == UINT16_MAX) || (offset_central_dir == UINT32_MAX)))
            {
                // Format should be Zip64, as the central directory or file size is too large
                central_pos = mz_zip_search_zip64_cd(zip->stream, central_pos);

                if (central_pos)
                {
                    if (mz_stream_seek(zip->stream, central_pos, MZ_STREAM_SEEK_SET) != 0)
                        err = MZ_STREAM_ERROR;

                    // The signature, already checked
                    if (mz_stream_read_uint32(zip->stream, &value32) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Size of zip64 end of central directory record
                    if (mz_stream_read_uint64(zip->stream, &value64) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Version made by
                    if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Version needed to extract
                    if (mz_stream_read_uint16(zip->stream, &value16) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Number of this disk
                    if (mz_stream_read_uint32(zip->stream, &zip->number_disk) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Number of the disk with the start of the central directory
                    if (mz_stream_read_uint32(zip->stream, &zip->number_disk_with_CD) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Total number of entries in the central directory on this disk
                    if (mz_stream_read_uint64(zip->stream, &number_entry) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Total number of entries in the central directory
                    if (mz_stream_read_uint64(zip->stream, &number_entry_CD) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    if (number_entry_CD != number_entry)
                        err = MZ_FORMAT_ERROR;
                    // Size of the central directory
                    if (mz_stream_read_uint64(zip->stream, &size_central_dir) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    // Offset of start of central directory with respect to the starting disk number
                    if (mz_stream_read_uint64(zip->stream, &offset_central_dir) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                }
                else
                {
                    err = MZ_FORMAT_ERROR;
                }
             }
        }

        if (err == MZ_OK)
        {
            if (central_pos < offset_central_dir + size_central_dir)
                err = MZ_FORMAT_ERROR;
        }

        if ((err == MZ_OK) && (comment_size > 0))
        {
            zip->comment = (char *)malloc(comment_size + 1);
            if (zip->comment)
            {
                if (mz_stream_read(zip->stream, zip->comment, comment_size) != comment_size)
                    err = MZ_STREAM_ERROR;
                zip->comment[comment_size] = 0;
            }
        }

        if (err == MZ_OK)
        {
            byte_before_the_zipfile = central_pos - (offset_central_dir + size_central_dir);
            zip->add_position_when_writting_offset = byte_before_the_zipfile;

            // Store central directory in memory
            if (mz_stream_seek(zip->stream, offset_central_dir + byte_before_the_zipfile, MZ_STREAM_SEEK_SET) != MZ_OK)
                err = MZ_STREAM_ERROR;
            if (mz_stream_copy(zip->cd_stream, zip->stream, (uint32_t)size_central_dir) != MZ_OK)
                err = MZ_STREAM_ERROR;

            zip->number_entry = number_entry_CD;

            if (mz_stream_seek(zip->stream, offset_central_dir + byte_before_the_zipfile, MZ_STREAM_SEEK_SET) != MZ_OK)
                err = MZ_STREAM_ERROR;
        }
    }
#endif

    if (err != MZ_OK)
    {
        mz_stream_close(zip->cd_stream);
        mz_stream_delete(&zip->cd_stream);

#ifndef NO_ADDFILEINEXISTINGZIP
        if (zip->comment)
            free(zip->comment);
#endif
        free(zip);
        return NULL;
    }

    return zip;
}

extern int ZEXPORT mz_zip_get_global_comment(void *handle, const char **global_comment)
{
    mz_zip *zip = NULL;

    if (handle == NULL || global_comment == NULL)
        return MZ_PARAM_ERROR;
    zip = (mz_zip*)handle;
    *global_comment = zip->comment;
    return MZ_OK;
}

extern int ZEXPORT mz_zip_entry_open(void *handle, const mz_zip_file *file_info,
    const mz_zip_compress *compress_info, const mz_zip_crypt *crypt_info)
{
    mz_zip *zip = NULL;
    uint16_t filename_size = 0;
    uint16_t version_needed = 0;
    int16_t err = MZ_OK;

#ifdef NOCRYPT
    if (password != NULL)
        return MZ_PARAM_ERROR;
#endif
    if (handle == NULL)
        return MZ_PARAM_ERROR;
    if (file_info == NULL || file_info->filename == NULL)
        return MZ_PARAM_ERROR;
    if (compress_info == NULL)
        return MZ_PARAM_ERROR;
    if (crypt_info == NULL)
        return MZ_PARAM_ERROR;

    switch (compress_info->method)
    {
    case MZ_METHOD_RAW:
    case MZ_METHOD_DEFLATE:
#ifdef HAVE_BZIP2
    case MZ_METHOD_BZIP2:
#endif
#if HAVE_LZMA
    case MZ_METHOD_LZMA:
#endif
        err = MZ_OK;
        break;
    default:
        return MZ_PARAM_ERROR;
    }

    zip = (mz_zip*)handle;

    if (zip->entry_opened == 1)
    {
        err = mz_zip_entry_close(handle);
        if (err != MZ_OK)
            return err;
    }

    memcpy(&zip->file_info, file_info, sizeof(mz_zip_file));
    memcpy(&zip->crypt_info, crypt_info, sizeof(mz_zip_crypt));
    memcpy(&zip->compress_info, compress_info, sizeof(mz_zip_compress));

    zip->file_info.flag |= 8; // data descriptor
#ifdef HAVE_LZMA
    zip->file_info.flag |= 2; // end of stream marker
#endif
    if ((zip->compress_info.level == 8) || (zip->compress_info.level == 9))
        zip->file_info.flag |= 2;
    if (zip->compress_info.level == 2)
        zip->file_info.flag |= 4;
    if (zip->compress_info.level == 1)
        zip->file_info.flag |= 6;

    if (zip->crypt_info.password != NULL)
        zip->file_info.flag |= 1;
    else
        zip->file_info.flag &= ~1;

    filename_size = (uint16_t)strlen(zip->file_info.filename);

    zip->pos_local_header = mz_stream_tell(zip->stream);
    if (zip->pos_local_header >= UINT32_MAX)
        zip->file_info.zip64 = 1;

    // Write the local header
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, (uint32_t)LOCALHEADERMAGIC);

    version_needed = 20;
    if (zip->file_info.zip64)
        version_needed = 45;
#ifdef HAVE_AES
    if ((zip->file_info.flag & 1) && (zip->crypt_info.aes))
        version_needed = 51;
#endif
#ifdef HAVE_LZMA
    if (zip->compress_info.method == MZ_METHOD_LZMA)
        version_needed = 63;
#endif

    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, version_needed);
    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, zip->file_info.flag);
    if (err == MZ_OK)
    {
#ifdef HAVE_AES
        if ((zip->file_info.flag & 1) && (zip->crypt_info.aes))
            err = mz_stream_write_uint16(zip->stream, MZ_AES_METHOD);
        else
#endif
            err = mz_stream_write_uint16(zip->stream, zip->compress_info.method);
    }
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, zip->file_info.dos_date);

    // CRC & compressed size & uncompressed size is in data descriptor
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, 0); // crc 32
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, 0); // compressed size
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, 0); // uncompressed size
    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, filename_size);
    if (err == MZ_OK)
    {
        uint16_t extrafield_size = zip->file_info.extrafield_local_size;
#ifdef HAVE_AES
        if ((zip->file_info.flag & 1) && (zip->crypt_info.aes))
            extrafield_size += 4 + 7;
#endif
        err = mz_stream_write_uint16(zip->stream, extrafield_size);
    }
    if (err == MZ_OK)
    {
        if (mz_stream_write(zip->stream, zip->file_info.filename, filename_size) != filename_size)
            err = MZ_STREAM_ERROR;
    }
    if (err == MZ_OK)
    {
        if (mz_stream_write(zip->stream, zip->file_info.extrafield_local, 
                zip->file_info.extrafield_local_size) != zip->file_info.extrafield_local_size)
            err = MZ_STREAM_ERROR;
    }

#ifdef HAVE_AES
    // Write the AES extended info
    if ((err == MZ_OK) && (zip->file_info.flag & 1) && (zip->crypt_info.aes))
    {
        err = mz_stream_write_uint16(zip->stream, 0x9901);
        if (err == MZ_OK)
            err = mz_stream_write_uint16(zip->stream, 7);
        if (err == MZ_OK)
            err = mz_stream_write_uint16(zip->stream, MZ_AES_VERSION);
        if (err == MZ_OK)
            err = mz_stream_write_uint8(zip->stream, 'A');
        if (err == MZ_OK)
            err = mz_stream_write_uint8(zip->stream, 'E');
        if (err == MZ_OK)
            err = mz_stream_write_uint8(zip->stream, MZ_AES_ENCRYPTIONMODE);
        if (err == MZ_OK)
            err = mz_stream_write_uint16(zip->stream, zip->compress_info.method);
    }
#endif

#ifndef NOCRYPT
    if (err == Z_OK)
    {
        if (zip->crypt_info.password == NULL)
        {
            mz_stream_passthru_create(&zip->crypt_stream);
            mz_stream_set_base(zip->crypt_stream, zip->stream);
        }
#ifdef HAVE_AES
        else if (zip->crypt_info.aes)
        {
            mz_stream_aes_create(&zip->crypt_stream);
            mz_stream_aes_set_password(zip->crypt_stream, zip->crypt_info.password);
            
            mz_stream_set_base(zip->crypt_stream, zip->stream);

            if (mz_stream_open(zip->crypt_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
        else
#endif
        {
            uint8_t verify1 = 0;
            uint8_t verify2 = 0;

            // Info-ZIP modification to ZipCrypto format:
            // If bit 3 of the general purpose bit flag is set, it uses high byte of 16-bit File Time.

            verify1 = (uint8_t)((zip->file_info.dos_date >> 16) & 0xff);
            verify2 = (uint8_t)((zip->file_info.dos_date >> 8) & 0xff);

            mz_stream_crypt_create(&zip->crypt_stream);
            mz_stream_crypt_set_password(zip->crypt_stream, zip->crypt_info.password);
            mz_stream_crypt_set_verify(zip->crypt_stream, verify1, verify2);

            mz_stream_set_base(zip->crypt_stream, zip->stream);

            if (mz_stream_open(zip->crypt_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
    }
#endif

    if (err == MZ_OK)
    {
        if (zip->compress_info.method == 0) // raw
        {
            mz_stream_passthru_create(&zip->compress_stream);
            mz_stream_set_base(zip->compress_stream, zip->crypt_stream);
        }
        else if (zip->compress_info.method == MZ_METHOD_DEFLATE)
        {
            mz_stream_zlib_create(&zip->compress_stream);
            mz_stream_zlib_set_level(zip->compress_stream, zip->compress_info.level);
            mz_stream_zlib_set_window_bits(zip->compress_stream, zip->compress_info.window_bits);
            mz_stream_zlib_set_mem_level(zip->compress_stream, zip->compress_info.mem_level);
            mz_stream_zlib_set_strategy(zip->compress_stream, zip->compress_info.strategy);

            mz_stream_set_base(zip->compress_stream, zip->crypt_stream);

            if (mz_stream_open(zip->compress_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#ifdef HAVE_BZIP2
        else if (zip->compress_info.method == MZ_METHOD_BZIP2)
        {
            mz_stream_bzip_create(&zip->compress_stream);
            mz_stream_bzip_set_level(zip->compress_stream, zip->compress_info.level);

            mz_stream_set_base(zip->compress_stream, zip->crypt_stream);

            if (mz_stream_open(zip->compress_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#endif
#ifdef HAVE_LZMA
        else if (zip->compress_info.method == MZ_METHOD_LZMA)
        {
            mz_stream_lzma_create(&zip->compress_stream);
            mz_stream_lzma_set_level(zip->compress_stream, zip->compress_info.level);

            mz_stream_set_base(zip->compress_stream, zip->crypt_stream);

            if (mz_stream_open(zip->compress_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#endif
    }

    if (err == Z_OK)
    {
        mz_stream_crc32_create(&zip->crc32_stream);
        mz_stream_set_base(zip->crc32_stream, zip->compress_stream);

        if (mz_stream_open(zip->crc32_stream, NULL, MZ_STREAM_MODE_WRITE) != MZ_OK)
            err = MZ_INTERNAL_ERROR;
    }

    if (err == Z_OK)
        zip->entry_opened = 1;

    return err;
}

extern int ZEXPORT mz_zip_entry_write(void *handle, const void *buf, uint32_t len)
{
    mz_zip *zip = NULL;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    zip = (mz_zip*)handle;

    if (zip->entry_opened == 0)
        return MZ_PARAM_ERROR;
    if (mz_stream_write(zip->crc32_stream, buf, len) == MZ_STREAM_ERROR)
        return MZ_STREAM_ERROR;

    return MZ_OK;
}

extern int ZEXPORT mz_zip_entry_close_raw(void *handle, uint64_t uncompressed_size, uint32_t crc32)
{
    mz_zip *zip = NULL;
    uint64_t compressed_size = 0;
    uint16_t extrafield_size = 0;
    uint16_t extrafield_zip64_size = 0;
    uint16_t filename_size = 0;
    uint16_t comment_size = 0;
    uint16_t version_needed = 0;
    int16_t err = MZ_OK;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    zip = (mz_zip*)handle;

    if (zip->entry_opened == 0)
        return MZ_PARAM_ERROR;
  
    mz_stream_close(zip->compress_stream);
    
    if ((zip->compress_info.method != 0) || (uncompressed_size == 0))
    {
        crc32 = mz_stream_crc32_get_value(zip->crc32_stream);
        uncompressed_size = mz_stream_get_total_out(zip->crc32_stream);
        compressed_size = mz_stream_get_total_out(zip->compress_stream);
    }

    if (zip->file_info.flag & 1)
    {
        mz_stream_set_base(zip->crypt_stream, zip->stream);

        err = mz_stream_close(zip->crypt_stream);

        if ((zip->compress_info.method != 0) || (uncompressed_size == 0))
            compressed_size = mz_stream_get_total_out(zip->crypt_stream);

        mz_stream_delete(&zip->crypt_stream);
    }

    mz_stream_delete(&zip->compress_stream);
    mz_stream_crc32_delete(&zip->crc32_stream);

    // Write data descriptor
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, (uint32_t)DATADESCRIPTORMAGIC);
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, crc32);
    if (err == MZ_OK)
    {
        if (zip->file_info.zip64)
            err = mz_stream_write_uint64(zip->stream, compressed_size);
        else
            err = mz_stream_write_uint32(zip->stream, (uint32_t)compressed_size);
    }
    if (err == MZ_OK)
    {
        if (zip->file_info.zip64)
            err = mz_stream_write_uint64(zip->stream, uncompressed_size);
        else
            err = mz_stream_write_uint32(zip->stream, (uint32_t)uncompressed_size);
    }

    // Write central directory header

    // Calculate extra field size
    version_needed = 20;
    extrafield_size = zip->file_info.extrafield_global_size;
    if (zip->file_info.zip64)
    {
        version_needed = 45;
        extrafield_zip64_size += 4;
        if (uncompressed_size >= UINT32_MAX)
            extrafield_zip64_size += 8;
        if (compressed_size >= UINT32_MAX)
            extrafield_zip64_size += 8;
        if (zip->pos_local_header >= UINT32_MAX)
            extrafield_zip64_size += 8;
        extrafield_size += extrafield_zip64_size;
    }
#ifdef HAVE_AES
    if ((zip->file_info.flag & 1) && (zip->crypt_info.aes))
    {
        version_needed = 51;
        extrafield_size += 4 + 7;
    }
#endif
#ifdef HAVE_LZMA
    if (zip->compress_info.method == MZ_METHOD_LZMA)
        version_needed = 63;
#endif

    filename_size = (uint16_t)strlen(zip->file_info.filename);
    if (zip->file_info.comment != NULL)
        comment_size = (uint16_t)strlen(zip->file_info.comment);

    mz_stream_write_uint32(zip->cd_stream, (uint32_t)CENTRALHEADERMAGIC);
    mz_stream_write_uint16(zip->cd_stream, zip->file_info.version_madeby);
    mz_stream_write_uint16(zip->cd_stream, version_needed);
    mz_stream_write_uint16(zip->cd_stream, zip->file_info.flag);
    mz_stream_write_uint16(zip->cd_stream, zip->compress_info.method);
    mz_stream_write_uint32(zip->cd_stream, zip->file_info.dos_date);

    mz_stream_write_uint32(zip->cd_stream, crc32); // crc
    if (compressed_size >= UINT32_MAX) // compr size
        mz_stream_write_uint32(zip->cd_stream, UINT32_MAX); 
    else
        mz_stream_write_uint32(zip->cd_stream, (uint32_t)compressed_size);
    if (uncompressed_size >= UINT32_MAX) // uncompr size
        mz_stream_write_uint32(zip->cd_stream, UINT32_MAX);
    else
        mz_stream_write_uint32(zip->cd_stream, (uint32_t)uncompressed_size);

    mz_stream_write_uint16(zip->cd_stream, filename_size);
    mz_stream_write_uint16(zip->cd_stream, extrafield_size);
    mz_stream_write_uint16(zip->cd_stream, comment_size);
    mz_stream_write_uint16(zip->cd_stream, (uint16_t)zip->number_disk); // disk nm start
    mz_stream_write_uint16(zip->cd_stream, zip->file_info.internal_fa);
    mz_stream_write_uint32(zip->cd_stream, zip->file_info.external_fa);

    if (zip->pos_local_header >= UINT32_MAX)
        mz_stream_write_uint32(zip->cd_stream, UINT32_MAX);
    else
        mz_stream_write_uint32(zip->cd_stream,
            (uint32_t)(zip->pos_local_header - zip->add_position_when_writting_offset));

    mz_stream_write(zip->cd_stream, zip->file_info.filename, filename_size);
    mz_stream_write(zip->cd_stream, zip->file_info.extrafield_global, zip->file_info.extrafield_global_size);

    // Add ZIP64 extra info header to central directory
    if (zip->file_info.zip64)
    {
        mz_stream_write_uint16(zip->cd_stream, 0x0001);
        mz_stream_write_uint16(zip->cd_stream, extrafield_zip64_size);

        if (uncompressed_size >= UINT32_MAX)
            mz_stream_write_uint64(zip->cd_stream, uncompressed_size);
        if (compressed_size >= UINT32_MAX)
            mz_stream_write_uint64(zip->cd_stream, compressed_size);
        if (zip->pos_local_header >= UINT32_MAX)
            mz_stream_write_uint64(zip->cd_stream, zip->pos_local_header);
    }

#ifdef HAVE_AES
    // Write AES extra info header to central directory
    if ((zip->file_info.flag & 1) && (zip->crypt_info.aes))
    {
        mz_stream_write_uint16(zip->cd_stream, 0x9901);
        mz_stream_write_uint16(zip->cd_stream, 7);

        mz_stream_write_uint16(zip->cd_stream, MZ_AES_VERSION);
        mz_stream_write_uint8(zip->cd_stream, 'A');
        mz_stream_write_uint8(zip->cd_stream, 'E');
        mz_stream_write_uint8(zip->cd_stream, MZ_AES_ENCRYPTIONMODE);
        mz_stream_write_uint16(zip->cd_stream, zip->compress_info.method);
    }
#endif
    // Write comment
    if (zip->file_info.comment != NULL)
    {
        mz_stream_write(zip->cd_stream, zip->file_info.comment, comment_size);
        free(zip->comment);
    }

    zip->number_entry += 1;
    zip->entry_opened = 0;

    return err;
}

extern int ZEXPORT mz_zip_entry_close(void *handle)
{
    return mz_zip_entry_close_raw(handle, 0, 0);
}

extern int ZEXPORT mz_zip_close(void *handle, const char *global_comment, uint16_t version_madeby)
{
    mz_zip *zip = NULL;
    uint32_t size_centraldir = 0;
    uint16_t comment_size = 0;
    uint64_t centraldir_pos_inzip = 0;
    uint64_t pos = 0;
    uint64_t cd_pos = 0;
    int16_t err = MZ_OK;

    if (handle == NULL)
        return MZ_PARAM_ERROR;
    zip = (mz_zip*)handle;

    if (zip->entry_opened == 1)
    {
        err = mz_zip_entry_close(handle);
        if (err != MZ_OK)
            return err;
    }

#ifndef NO_ADDFILEINEXISTINGZIP
    if (global_comment == NULL)
        global_comment = zip->comment;
#endif

    centraldir_pos_inzip = mz_stream_tell(zip->stream);

    mz_stream_seek(zip->cd_stream, 0, MZ_STREAM_SEEK_END);
    size_centraldir = (uint32_t)mz_stream_tell(zip->cd_stream);
    mz_stream_seek(zip->cd_stream, 0, MZ_STREAM_SEEK_SET);
    
    err = mz_stream_copy(zip->stream, zip->cd_stream, size_centraldir);

    mz_stream_close(zip->cd_stream);
    mz_stream_delete(&zip->cd_stream);

    pos = centraldir_pos_inzip - zip->add_position_when_writting_offset;

    // Write the ZIP64 central directory header
    if (pos >= UINT32_MAX || zip->number_entry > UINT32_MAX)
    {
        uint64_t zip64_eocd_pos_inzip = mz_stream_tell(zip->stream);

        err = mz_stream_write_uint32(zip->stream, (uint32_t)ZIP64ENDHEADERMAGIC);

        // Size of this 'zip64 end of central directory'
        if (err == MZ_OK)
            err = mz_stream_write_uint64(zip->stream, (uint64_t)44);
        // Version made by
        if (err == MZ_OK)
            err = mz_stream_write_uint16(zip->stream, version_madeby);
        // Version needed
        if (err == MZ_OK)
            err = mz_stream_write_uint16(zip->stream, (uint16_t)45);
        // Number of this disk
        if (err == MZ_OK)
            err = mz_stream_write_uint32(zip->stream, zip->number_disk_with_CD);
        // Number of the disk with the start of the central directory
        if (err == MZ_OK)
            err = mz_stream_write_uint32(zip->stream, zip->number_disk_with_CD);
        // Total number of entries in the central dir on this disk
        if (err == MZ_OK)
            err = mz_stream_write_uint64(zip->stream, zip->number_entry);
        // Total number of entries in the central dir
        if (err == MZ_OK)
            err = mz_stream_write_uint64(zip->stream, zip->number_entry);
        // Size of the central directory
        if (err == MZ_OK)
            err = mz_stream_write_uint64(zip->stream, (uint64_t)size_centraldir);

        if (err == MZ_OK)
        {
            // Offset of start of central directory with respect to the starting disk number
            cd_pos = centraldir_pos_inzip - zip->add_position_when_writting_offset;
            err = mz_stream_write_uint64(zip->stream, cd_pos);
        }
        if (err == MZ_OK)
            err = mz_stream_write_uint32(zip->stream, (uint32_t)ZIP64ENDLOCHEADERMAGIC);

        // Number of the disk with the start of the central directory
        if (err == MZ_OK)
            err = mz_stream_write_uint32(zip->stream, zip->number_disk_with_CD);
        // Relative offset to the end of zip64 central directory
        if (err == MZ_OK)
        {
            cd_pos = zip64_eocd_pos_inzip - zip->add_position_when_writting_offset;
            err = mz_stream_write_uint64(zip->stream, cd_pos);
        }
        // Number of the disk with the start of the central directory
        if (err == MZ_OK)
            err = mz_stream_write_uint32(zip->stream, zip->number_disk_with_CD + 1);
    }

    // Write the central directory header

    // Signature 
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, (uint32_t)ENDHEADERMAGIC);
    // Number of this disk
    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, (uint16_t)zip->number_disk_with_CD);
    // Number of the disk with the start of the central directory
    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, (uint16_t)zip->number_disk_with_CD);
    // Total number of entries in the central dir on this disk
    if (err == MZ_OK)
    {
        if (zip->number_entry >= UINT16_MAX)
            err = mz_stream_write_uint16(zip->stream, UINT16_MAX);
        else
            err = mz_stream_write_uint16(zip->stream, (uint16_t)zip->number_entry);
    }
    // Total number of entries in the central dir
    if (err == MZ_OK)
    {
        if (zip->number_entry >= UINT16_MAX)
            err = mz_stream_write_uint16(zip->stream, UINT16_MAX);
        else
            err = mz_stream_write_uint16(zip->stream, (uint16_t)zip->number_entry);
    }
    // Size of the central directory
    if (err == MZ_OK)
        err = mz_stream_write_uint32(zip->stream, size_centraldir);
    // Offset of start of central directory with respect to the starting disk number
    if (err == MZ_OK)
    {
        cd_pos = centraldir_pos_inzip - zip->add_position_when_writting_offset;
        if (pos >= UINT32_MAX)
            err = mz_stream_write_uint32(zip->stream, UINT32_MAX);
        else
            err = mz_stream_write_uint32(zip->stream, (uint32_t)cd_pos);
    }

    // Write global comment
    if (global_comment != NULL)
        comment_size = (uint16_t)strlen(global_comment);
    if (err == MZ_OK)
        err = mz_stream_write_uint16(zip->stream, comment_size);
    if (err == MZ_OK)
    {
        if (mz_stream_write(zip->stream, global_comment, comment_size) != comment_size)
            err = MZ_STREAM_ERROR;
    }

#ifndef NO_ADDFILEINEXISTINGZIP
    if (zip->comment)
        free(zip->comment);
#endif
    free(zip);

    return err;
}
