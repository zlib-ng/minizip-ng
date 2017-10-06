/* unzip.c -- Zip manipulation
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2010-2017 Nathan Moinvaziri
     Modifications for AES, PKWARE disk spanning
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support on both zip and unzip
     http://result42.com
   Copyright (C) 2007-2008 Even Rouault
     Modifications of Unzip for Zip64
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
#include "mz_strm_aes.h"
#endif
#ifdef HAVE_BZIP2
#include "mz_strm_bzip.h"
#endif
#ifndef NOUNCRYPT
#  include "mz_strm_crypt.h"
#endif
#ifdef HAVE_LZMA
#include "mz_strm_lzma.h"
#endif
#include "mz_strm_mem.h"
#include "mz_strm_zlib.h"

#include "mz_unzip.h"

/***************************************************************************/

#define DISKHEADERMAGIC             (0x08074b50)
#define LOCALHEADERMAGIC            (0x04034b50)
#define CENTRALHEADERMAGIC          (0x02014b50)
#define ENDHEADERMAGIC              (0x06054b50)
#define ZIP64ENDHEADERMAGIC         (0x06064b50)
#define ZIP64ENDLOCHEADERMAGIC      (0x07064b50)

#define SIZECENTRALDIRITEM          (0x2e)
#define SIZECENTRALHEADERLOCATOR    (0x14)
#define SIZEZIPLOCALHEADER          (0x1e)

#ifndef BUFREADCOMMENT
#  define BUFREADCOMMENT            (0x400)
#endif

/***************************************************************************/

// Contains internal information about the zip file
typedef struct mz_unzip_s
{
    mz_unzip_global global_info;        // public global information
    mz_unzip_file   file_info;          // public file information

    void *stream;                       // main stream
    void *compress_stream;              // compression stream
    void *crc32_stream;                 // crc32 stream
    void *crypt_stream;                 // encryption stream
    void *file_info_stream;             // memory stream for storing file info

    uint64_t byte_before_the_zipfile;   // byte before the zip file, (>0 for sfx)
    uint64_t num_file;                  // number of the current file in the zip file
    uint64_t pos_in_central_dir;        // pos of the current file in the central dir
    uint64_t central_pos;               // position of the beginning of the central dir
    uint32_t number_disk;               // number of the current disk, used for spanning ZIP
    uint64_t size_central_dir;          // size of the central directory
    uint64_t offset_central_dir;        // offset of start of central directory with
                                        //   respect to the starting disk number

    uint64_t pos_in_zipfile;            // position in byte on the zip file, for fseek

    uint8_t  stream_initialised;        // flag set if stream structure is initialised
    uint64_t stream_available;          // number of byte to be decompressed

    uint64_t entry_header_read;         // flag about the usability of the current file

    uint64_t extrafield_local_offset;   // offset of the local extra field
    uint16_t extrafield_local_size;     // size of the local extra field
    uint64_t extrafield_local_pos;      // position in the local extra field in read

#ifdef HAVE_AES
    uint16_t aes_version;
    uint8_t  aes_encryption_mode;
#endif
} mz_unzip;

/***************************************************************************/

// Locate the central directory of a zip file (at the end, just before the global comment)
static uint64_t mz_unzip_search_cd(void *stream)
{
    uint8_t buf[BUFREADCOMMENT + 4];
    uint64_t file_size = 0;
    uint64_t back_read = 4;
    uint64_t max_back = UINT16_MAX; /* maximum size of global comment */
    uint64_t pos_found = 0;
    uint32_t read_size = 0;
    uint64_t read_pos = 0;
    uint32_t i = 0;

    if (mz_stream_seek(stream, 0, MZ_STREAM_SEEK_END) != 0)
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

        read_pos = file_size - back_read;
        read_size = ((BUFREADCOMMENT + 4) < (file_size - read_pos)) ?
                     (BUFREADCOMMENT + 4) : (uint32_t)(file_size - read_pos);

        if (mz_stream_seek(stream, read_pos, MZ_STREAM_SEEK_SET) != MZ_OK)
            break;
        if (mz_stream_read(stream, buf, read_size) != read_size)
            break;

        for (i = read_size - 3; (i--) > 0;)
        {
            if (((*(buf + i)) == (ENDHEADERMAGIC & 0xff)) &&
                ((*(buf + i + 1)) == (ENDHEADERMAGIC >> 8 & 0xff)) &&
                ((*(buf + i + 2)) == (ENDHEADERMAGIC >> 16 & 0xff)) &&
                ((*(buf + i + 3)) == (ENDHEADERMAGIC >> 24 & 0xff)))
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
static uint64_t mz_unzip_search_zip64_cd(void *stream, const uint64_t endcentraloffset)
{
    uint64_t offset = 0;
    uint32_t value32 = 0;

    // Zip64 end of central directory locator
    if (mz_stream_seek(stream, endcentraloffset - SIZECENTRALHEADERLOCATOR, MZ_STREAM_SEEK_SET) != 0)
        return 0;

    // Read locator signature
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    if (value32 != ZIP64ENDLOCHEADERMAGIC)
        return 0;
    // Number of the disk with the start of the zip64 end of  central directory
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    // Relative offset of the zip64 end of central directory record8
    if (mz_stream_read_uint64(stream, &offset) != MZ_OK)
        return 0;
    // Total number of disks
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    // Goto end of central directory record
    if (mz_stream_seek(stream, offset, MZ_STREAM_SEEK_SET) != MZ_OK)
        return 0;
     // The signature
    if (mz_stream_read_uint32(stream, &value32) != MZ_OK)
        return 0;
    if (value32 != ZIP64ENDHEADERMAGIC)
        return 0;

    return offset;
}

extern void* ZEXPORT mz_unzip_open(void *stream)
{
    mz_unzip *unzip = NULL;
    uint64_t central_pos = 0;
    uint64_t central_pos64 = 0;
    uint64_t number_entry_CD = 0;
    uint16_t value16 = 0;
    uint32_t value32 = 0;
    uint64_t value64 = 0;
    int16_t err = MZ_OK;


    unzip = (mz_unzip*)malloc(sizeof(mz_unzip));
    if (unzip == NULL)
        return NULL;

    memset(unzip, 0, sizeof(mz_unzip));

    unzip->stream = stream;

    // Search for end of central directory header
    central_pos = mz_unzip_search_cd(unzip->stream);
    if (central_pos)
    {
        if (mz_stream_seek(unzip->stream, central_pos, MZ_STREAM_SEEK_SET) != 0)
            err = MZ_STREAM_ERROR;

        // The signature, already checked
        if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
            err = MZ_STREAM_ERROR;
        // Number of this disk
        if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
            err = MZ_STREAM_ERROR;
        unzip->number_disk = value16;
        // Number of the disk with the start of the central directory
        if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
            err = MZ_STREAM_ERROR;
        unzip->global_info.number_disk_with_CD = value16;
        // Total number of entries in the central directory on this disk
        if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
            err = MZ_STREAM_ERROR;
        unzip->global_info.number_entry = value16;
        // Total number of entries in the central directory
        if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
            err = MZ_STREAM_ERROR;
        number_entry_CD = value16;
        if (number_entry_CD != unzip->global_info.number_entry)
            err = MZ_FORMAT_ERROR;
        // Size of the central directory
        if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
            err = MZ_STREAM_ERROR;
        unzip->size_central_dir = value32;
        // Offset of start of central directory with respect to the starting disk number
        if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
            err = MZ_STREAM_ERROR;
        unzip->offset_central_dir = value32;
        // Zipfile comment length
        if (mz_stream_read_uint16(unzip->stream, &unzip->global_info.comment_size) != MZ_OK)
            err = MZ_STREAM_ERROR;
    }

    if (err == MZ_OK)
    {
        // Search for Zip64 end of central directory header
        central_pos64 = mz_unzip_search_zip64_cd(unzip->stream, central_pos);
        if (central_pos64)
        {
            central_pos = central_pos64;

            if (mz_stream_seek(unzip->stream, central_pos, MZ_STREAM_SEEK_SET) != 0)
                err = MZ_STREAM_ERROR;

            // The signature, already checked
            if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Size of zip64 end of central directory record
            if (mz_stream_read_uint64(unzip->stream, &value64) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Version made by
            if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Version needed to extract
            if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Number of this disk
            if (mz_stream_read_uint32(unzip->stream, &unzip->number_disk) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Number of the disk with the start of the central directory
            if (mz_stream_read_uint32(unzip->stream, &unzip->global_info.number_disk_with_CD) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Total number of entries in the central directory on this disk
            if (mz_stream_read_uint64(unzip->stream, &unzip->global_info.number_entry) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Total number of entries in the central directory
            if (mz_stream_read_uint64(unzip->stream, &number_entry_CD) != MZ_OK)
                err = MZ_STREAM_ERROR;
            if (number_entry_CD != unzip->global_info.number_entry)
                err = MZ_FORMAT_ERROR;
            // Size of the central directory
            if (mz_stream_read_uint64(unzip->stream, &unzip->size_central_dir) != MZ_OK)
                err = MZ_STREAM_ERROR;
            // Offset of start of central directory with respect to the starting disk number
            if (mz_stream_read_uint64(unzip->stream, &unzip->offset_central_dir) != MZ_OK)
                err = MZ_STREAM_ERROR;
        }
        else if ((unzip->global_info.number_entry == UINT16_MAX) || (unzip->size_central_dir == UINT16_MAX) ||
                 (unzip->offset_central_dir == UINT32_MAX))
        {
            err = MZ_FORMAT_ERROR;
        }
    }

    if (err == MZ_OK)
    {
        if (central_pos < unzip->offset_central_dir + unzip->size_central_dir)
            err = MZ_FORMAT_ERROR;
    }

    if (err == MZ_OK)
    {
        // Hack for zip files that have no respect for zip64
        //if ((central_pos > 0xffffffff) && (unzip->offset_central_dir < 0xffffffff))
        //    unzip->offset_central_dir = central_pos - unzip->size_central_dir;

        unzip->byte_before_the_zipfile = central_pos - (unzip->offset_central_dir + unzip->size_central_dir);
        unzip->central_pos = central_pos;
    }

    if (err == MZ_OK)
    {
        mz_stream_mem_create(&unzip->file_info_stream);
        mz_stream_mem_set_grow(unzip->file_info_stream, 1);
        mz_stream_mem_set_grow_size(unzip->file_info_stream, 4096);

        err = mz_stream_mem_open(unzip->file_info_stream, NULL, MZ_STREAM_MODE_CREATE);
    }

    if (err != MZ_OK)
    {
        if (unzip->file_info_stream != NULL)
            mz_stream_mem_delete(&unzip->file_info_stream);

        free(unzip);
        return NULL;
    }
    
    return unzip;
}

extern int ZEXPORT mz_unzip_close(void *handle)
{
    mz_unzip *unzip = NULL;

    if (handle == NULL)
        return MZ_PARAM_ERROR;
    unzip = (mz_unzip*)handle;

    if (unzip->stream_initialised != 0)
        mz_unzip_entry_close(handle);

    mz_stream_mem_close(unzip->file_info_stream);
    mz_stream_mem_delete(&unzip->file_info_stream);

    free(unzip);
    return MZ_OK;
}

extern int ZEXPORT mz_unzip_get_global_info(void *handle, mz_unzip_global *global_info)
{
    mz_unzip *unzip = NULL;
    if (handle == NULL)
        return MZ_PARAM_ERROR;
    unzip = (mz_unzip*)handle;
    *global_info = unzip->global_info;
    return MZ_OK;
}

extern int ZEXPORT mz_unzip_get_global_comment(void *handle, char *comment, uint16_t comment_size)
{
    mz_unzip *unzip = NULL;
    uint16_t bytes_to_read = comment_size;

    if (handle == NULL)
        return (int)MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (comment_size > 1)
        *comment = 0;

    if (bytes_to_read > unzip->global_info.comment_size)
        bytes_to_read = unzip->global_info.comment_size;

    if (mz_stream_seek(unzip->stream, unzip->central_pos + 22, MZ_STREAM_SEEK_SET) != MZ_OK)
        return MZ_STREAM_ERROR;

    if (bytes_to_read > 0)
    {
        if (mz_stream_read(unzip->stream, comment, bytes_to_read) != bytes_to_read)
            return MZ_STREAM_ERROR;
    }

    if ((comment != NULL) && (comment_size > unzip->global_info.comment_size))
        *(comment + unzip->global_info.comment_size) = 0;

    return MZ_OK;
}

// Get info about the current file in the zip file
static int mz_unzip_entry_read_header(void *handle)
{
    mz_unzip *unzip = NULL;
    uint32_t magic = 0;
    uint32_t extra_pos = 0;
    uint16_t extra_header_id = 0;
    uint16_t extra_data_size = 0;
    uint16_t value16 = 0;
    uint32_t value32 = 0;
    uint64_t value64 = 0;
    int64_t seek = 0;
    int16_t err = MZ_OK;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;
    unzip->entry_header_read = 0;
    
    memset(&unzip->file_info, 0, sizeof(mz_unzip_file));

    if (mz_stream_seek(unzip->stream,
            unzip->pos_in_central_dir + unzip->byte_before_the_zipfile, MZ_STREAM_SEEK_SET) != MZ_OK)
        err = MZ_STREAM_ERROR;

    // Check the magic
    if (err == MZ_OK)
    {
        if (mz_stream_read_uint32(unzip->stream, &magic) != MZ_OK)
            err = MZ_STREAM_ERROR;
        else if (magic != CENTRALHEADERMAGIC)
            err = MZ_FORMAT_ERROR;
    }

    // Read central directory header
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.version) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.version_needed) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.flag) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.compression_method) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &unzip->file_info.dos_date) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &unzip->file_info.crc) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
        err = MZ_STREAM_ERROR;
    unzip->file_info.compressed_size = value32;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
        err = MZ_STREAM_ERROR;
    unzip->file_info.uncompressed_size = value32;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.filename_size) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.extrafield_size) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.comment_size) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
        err = MZ_STREAM_ERROR;
    unzip->file_info.disk_num_start = value16;
    if (mz_stream_read_uint16(unzip->stream, &unzip->file_info.internal_fa) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &unzip->file_info.external_fa) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK)
        err = MZ_STREAM_ERROR;
    unzip->file_info.disk_offset = value32;

#ifdef HAVE_AES
    unzip->aes_version = 0;
    unzip->aes_encryption_mode = 0;
#endif

    if ((err == MZ_OK) && (unzip->file_info.filename_size > 0))
    {
        // Read filename in our memory stream buffer
        mz_stream_mem_get_buffer(unzip->file_info_stream, (void **)&unzip->file_info.filename);

        if (mz_stream_seek(unzip->file_info_stream, 0, MZ_STREAM_SEEK_SET) != MZ_OK)
            err = MZ_STREAM_ERROR;
        if (mz_stream_copy(unzip->file_info_stream, unzip->stream, unzip->file_info.filename_size) != MZ_OK)
            err = MZ_STREAM_ERROR;
        if (mz_stream_write_uint8(unzip->file_info_stream, 0) != MZ_OK)
            err = MZ_STREAM_ERROR;

        seek += unzip->file_info.filename_size + 1;
    }

    if ((err == MZ_OK) && (unzip->file_info.extrafield_size > 0))
    {
        mz_stream_mem_get_buffer_at(unzip->file_info_stream, seek, (void **)&unzip->file_info.extrafield);

        if (mz_stream_copy(unzip->file_info_stream, unzip->stream, unzip->file_info.extrafield_size) != MZ_OK)
            err = MZ_STREAM_ERROR;
        if (mz_stream_write_uint8(unzip->file_info_stream, 0) != MZ_OK)
            err = MZ_STREAM_ERROR;

        // Seek back and parse the extra field
        if (mz_stream_seek(unzip->file_info_stream, seek, MZ_STREAM_SEEK_SET) != MZ_OK)
            err = MZ_STREAM_ERROR;

        seek += unzip->file_info.extrafield_size + 1;

        while ((err == MZ_OK) && (extra_pos < unzip->file_info.extrafield_size))
        {
            if (mz_stream_read_uint16(unzip->file_info_stream, &extra_header_id) != MZ_OK)
                err = MZ_STREAM_ERROR;
            if (mz_stream_read_uint16(unzip->file_info_stream, &extra_data_size) != MZ_OK)
                err = MZ_STREAM_ERROR;

            // ZIP64 extra field
            if (extra_header_id == 0x0001)
            {
                if (unzip->file_info.uncompressed_size == UINT32_MAX)
                {
                    if (mz_stream_read_uint64(unzip->file_info_stream, &unzip->file_info.uncompressed_size) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                }
                if (unzip->file_info.compressed_size == UINT32_MAX)
                {
                    if (mz_stream_read_uint64(unzip->file_info_stream, &unzip->file_info.compressed_size) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                }
                if (unzip->file_info.disk_offset == UINT32_MAX)
                {
                    // Relative Header offset
                    if (mz_stream_read_uint64(unzip->file_info_stream, &value64) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                    unzip->file_info.disk_offset = value64;
                }
                if (unzip->file_info.disk_num_start == UINT32_MAX)
                {
                    // Disk Start Number
                    if (mz_stream_read_uint32(unzip->file_info_stream, &unzip->file_info.disk_num_start) != MZ_OK)
                        err = MZ_STREAM_ERROR;
                }
            }
#ifdef HAVE_AES
            // AES extra field
            else if (extra_header_id == 0x9901)
            {
                uint8_t value8 = 0;

                // Verify version info
                if (mz_stream_read_uint16(unzip->file_info_stream, &value16) != MZ_OK)
                    err = MZ_STREAM_ERROR;
                // Support AE-1 and AE-2
                if (value16 != 1 && value16 != 2)
                    err = MZ_FORMAT_ERROR;
                unzip->aes_version = value16;
                if (mz_stream_read_uint8(unzip->file_info_stream, &value8) != MZ_OK)
                    err = MZ_STREAM_ERROR;
                if ((char)value8 != 'A')
                    err = MZ_FORMAT_ERROR;
                if (mz_stream_read_uint8(unzip->file_info_stream, &value8) != MZ_OK)
                    err = MZ_STREAM_ERROR;
                if ((char)value8 != 'E')
                    err = MZ_FORMAT_ERROR;
                // Get AES encryption strength and actual compression method
                if (mz_stream_read_uint8(unzip->file_info_stream, &value8) != MZ_OK)
                    err = MZ_STREAM_ERROR;
                unzip->aes_encryption_mode = value8;
                if (mz_stream_read_uint16(unzip->file_info_stream, &value16) != MZ_OK)
                    err = MZ_STREAM_ERROR;
                unzip->file_info.compression_method = value16;
            }
#endif
            else
            {
                if (mz_stream_seek(unzip->file_info_stream, extra_data_size, MZ_STREAM_SEEK_CUR) != MZ_OK)
                    err = MZ_STREAM_ERROR;
            }

            extra_pos += 4 + extra_data_size;
        }
    }

    if ((err == MZ_OK) && (unzip->file_info.comment_size > 0))
    {
        mz_stream_mem_get_buffer_at(unzip->file_info_stream, seek, (void **)&unzip->file_info.comment);

        if (mz_stream_copy(unzip->file_info_stream, unzip->stream, unzip->file_info.comment_size) != MZ_OK)
            err = MZ_STREAM_ERROR;
        if (mz_stream_write_uint8(unzip->file_info_stream, 0) != MZ_OK)
            err = MZ_STREAM_ERROR;
    }

    if (err == MZ_OK)
    {
        unzip->entry_header_read = 1;
        unzip->stream_available = unzip->file_info.uncompressed_size;
    }

    return err;
}

// Read the local header of the current zip file. Check the coherency of the local header and info in the
// end of central directory about this file store in extrainfo_size the size of extra info in local header
// (filename and size of extra field data)
static int mz_unzip_entry_check_header(mz_unzip *unzip, uint32_t *extrainfo_size, uint64_t *extrafield_local_offset,
    uint16_t *extrafield_local_size)
{
    uint32_t magic = 0;
    uint16_t value16 = 0;
    uint32_t value32 = 0;
    uint32_t flags = 0;
    uint16_t filename_size = 0;
    uint16_t extrafield_size = 0;
    int err = MZ_OK;

    if (extrainfo_size == NULL)
        return MZ_PARAM_ERROR;
    *extrainfo_size = 0;
    if (extrafield_local_offset == NULL)
        return MZ_PARAM_ERROR;
    *extrafield_local_offset = 0;
    if (extrafield_local_size == NULL)
        return MZ_PARAM_ERROR;
    *extrafield_local_size = 0;

    if (err != MZ_OK)
        return err;

    if (mz_stream_seek(unzip->stream, unzip->file_info.disk_offset +
            unzip->byte_before_the_zipfile, MZ_STREAM_SEEK_SET) != MZ_OK)
        return MZ_STREAM_ERROR;

    if (err == MZ_OK)
    {
        if (mz_stream_read_uint32(unzip->stream, &magic) != MZ_OK)
            err = MZ_STREAM_ERROR;
        else if (magic != LOCALHEADERMAGIC)
            err = MZ_FORMAT_ERROR;
    }

    if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
        err = MZ_STREAM_ERROR;
    flags = value16;
    if (mz_stream_read_uint16(unzip->stream, &value16) != MZ_OK)
        err = MZ_STREAM_ERROR;
    else if ((err == MZ_OK) && (value16 != unzip->file_info.compression_method))
    {
#ifdef HAVE_AES
        if (value16 != MZ_AES_METHOD)
            err = MZ_FORMAT_ERROR;
#else
        err = MZ_FORMAT_ERROR;
#endif
    }
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK) // date/time
        err = MZ_STREAM_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK) // crc
        err = MZ_STREAM_ERROR;
    else if ((err == MZ_OK) && (value32 != unzip->file_info.crc) && ((flags & 8) == 0))
        err = MZ_FORMAT_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK) // size compr
        err = MZ_STREAM_ERROR;
    else if ((value32 != UINT32_MAX) && (err == MZ_OK) && (value32 != unzip->file_info.compressed_size) && ((flags & 8) == 0))
        err = MZ_FORMAT_ERROR;
    if (mz_stream_read_uint32(unzip->stream, &value32) != MZ_OK) // size uncompr
        err = MZ_STREAM_ERROR;
    else if ((value32 != UINT32_MAX) && (err == MZ_OK) && (value32 != unzip->file_info.uncompressed_size) && ((flags & 8) == 0))
        err = MZ_FORMAT_ERROR;
    if (mz_stream_read_uint16(unzip->stream, &filename_size) != MZ_OK)
        err = MZ_STREAM_ERROR;
    else if ((err == MZ_OK) && (filename_size != unzip->file_info.filename_size))
        err = MZ_FORMAT_ERROR;

    *extrainfo_size += filename_size;

    if (mz_stream_read_uint16(unzip->stream, &extrafield_size) != MZ_OK)
        err = MZ_STREAM_ERROR;

    *extrafield_local_offset = unzip->file_info.disk_offset + SIZEZIPLOCALHEADER + filename_size;
    *extrafield_local_size = extrafield_size;
    *extrainfo_size += extrafield_size;

    return err;
}

extern int ZEXPORT mz_unzip_entry_open(void *handle, int raw, const char *password)
{
    mz_unzip *unzip = NULL;
    uint64_t extrafield_local_offset = 0;
    uint16_t extrafield_local_size = 0;
    uint32_t size_variable = 0;
    int64_t max_total_in = 0;
    int16_t err = MZ_OK;

#ifdef NOUNCRYPT
    if (password != NULL)
        return MZ_PARAM_ERROR;
#endif
    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (unzip->entry_header_read == 0)
        return MZ_PARAM_ERROR;
    if ((unzip->file_info.flag & 1) && (password == NULL))
        return MZ_PARAM_ERROR;

    err = mz_unzip_entry_check_header(unzip, &size_variable, &extrafield_local_offset, &extrafield_local_size);
    if (err != MZ_OK)
        return err;
    
    if ((unzip->file_info.compression_method != 0) && 
        (unzip->file_info.compression_method != MZ_METHOD_DEFLATE))
    {
#ifdef HAVE_BZIP2
        if (unzip->file_info.compression_method != MZ_METHOD_BZIP2)
            return MZ_FORMAT_ERROR;
#elif HAVE_LZMA
        if (unzip->file_info.compression_method != MZ_METHOD_LZMA)
            return MZ_FORMAT_ERROR;
#else
        return MZ_FORMAT_ERROR;
#endif
    }


    unzip->extrafield_local_offset = extrafield_local_offset;
    unzip->extrafield_local_size = extrafield_local_size;
    unzip->extrafield_local_pos = 0;

    unzip->byte_before_the_zipfile = 0;

    if (unzip->number_disk == unzip->global_info.number_disk_with_CD)
        unzip->byte_before_the_zipfile = unzip->byte_before_the_zipfile;
        
    unzip->pos_in_zipfile = unzip->file_info.disk_offset + 
        SIZEZIPLOCALHEADER + size_variable;

    if (err == MZ_OK)
    {
        if (mz_stream_seek(unzip->stream,
                unzip->pos_in_zipfile + unzip->byte_before_the_zipfile, MZ_STREAM_SEEK_SET) != MZ_OK)
            err = MZ_INTERNAL_ERROR;
    }

    max_total_in = unzip->file_info.compressed_size;

#ifndef NOUNCRYPT
    if (unzip->file_info.flag & 1)
    {
#ifdef HAVE_AES
        if (unzip->aes_version > 0)
        {
            mz_stream_aes_create(&unzip->crypt_stream);
            mz_stream_aes_set_password(unzip->crypt_stream, password);
            mz_stream_aes_set_encryption_mode(unzip->crypt_stream, unzip->aes_encryption_mode);

            max_total_in -= mz_stream_aes_get_footer_size(unzip->crypt_stream);

            mz_stream_set_base(unzip->crypt_stream, unzip->stream);

            if (mz_stream_open(unzip->crypt_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
        else
#endif
        {
            mz_stream_crypt_create(&unzip->crypt_stream);
            mz_stream_crypt_set_password(unzip->crypt_stream, password);

            mz_stream_set_base(unzip->crypt_stream, unzip->stream);

            if (mz_stream_open(unzip->crypt_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
                err = MZ_STREAM_ERROR;
        }
#endif
    }
    if (unzip->crypt_stream == NULL)
    {
        mz_stream_passthru_create(&unzip->crypt_stream);
        mz_stream_set_base(unzip->crypt_stream, unzip->stream);
    }

    max_total_in -= mz_stream_get_total_in(unzip->crypt_stream);
    
    if (err == MZ_OK)
    {
        if (raw || unzip->file_info.compression_method == 0)
        {
            mz_stream_passthru_create(&unzip->compress_stream);
            mz_stream_set_base(unzip->compress_stream, unzip->crypt_stream);
        }
        else if (unzip->file_info.compression_method == MZ_METHOD_DEFLATE)
        {
            mz_stream_zlib_create(&unzip->compress_stream);
            if (unzip->file_info.flag & 1)
                mz_stream_zlib_set_max_total_in(unzip->compress_stream, max_total_in);

            mz_stream_set_base(unzip->compress_stream, unzip->crypt_stream);

            if (mz_stream_open(unzip->compress_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#ifdef HAVE_BZIP2
        else if (unzip->file_info.compression_method == MZ_METHOD_BZIP2)
        {
            mz_stream_bzip_create(&unzip->compress_stream);
            if (unzip->file_info.flag & 1)
                mz_stream_bzip_set_max_total_in(unzip->compress_stream, max_total_in);

            mz_stream_set_base(unzip->compress_stream, unzip->crypt_stream);

            if (mz_stream_open(unzip->compress_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#endif
#ifdef HAVE_LZMA
        else if (unzip->file_info.compression_method == MZ_METHOD_LZMA)
        {
            mz_stream_lzma_create(&unzip->compress_stream);
            if (unzip->file_info.flag & 1)
                mz_stream_lzma_set_max_total_in(unzip->compress_stream, max_total_in);

            mz_stream_set_base(unzip->compress_stream, unzip->crypt_stream);

            if (mz_stream_open(unzip->compress_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
                err = MZ_INTERNAL_ERROR;
        }
#endif

    }
    if (err == MZ_OK)
    {
        mz_stream_crc32_create(&unzip->crc32_stream);
        mz_stream_set_base(unzip->crc32_stream, unzip->compress_stream);

        if (mz_stream_open(unzip->crc32_stream, NULL, MZ_STREAM_MODE_READ) != MZ_OK)
            err = MZ_INTERNAL_ERROR;
    }

    if (err == MZ_OK)
    {
        unzip->stream_initialised = 1;
    }

    return err;
}

extern int ZEXPORT mz_unzip_entry_read(void *handle, void *buf, uint32_t len)
{
    mz_unzip *unzip = NULL;
    uint32_t read = 0;

    if (handle == NULL)
        return MZ_PARAM_ERROR;
    unzip = (mz_unzip*)handle;

    if (unzip->stream_initialised == 0)
        return MZ_PARAM_ERROR;

    if (len == 0)
        return 0;
    if (len > UINT16_MAX)
        return MZ_PARAM_ERROR;
    
    if (len > unzip->stream_available)
        len = (uint32_t)unzip->stream_available;

    read = mz_stream_read(unzip->crc32_stream, buf, len);

    if (read > 0)
        unzip->stream_available -= read;

    return read;
}

extern int ZEXPORT mz_unzip_entry_get_info(void *handle, mz_unzip_file **file_info)
{
    mz_unzip *unzip = NULL;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (unzip->entry_header_read == 0)
        return MZ_PARAM_ERROR;

    *file_info = &unzip->file_info;
    return MZ_OK;
}

extern int ZEXPORT mz_unzip_entry_get_extrafield_local(void *handle, void *buf, uint32_t len)
{
    mz_unzip *unzip = NULL;
    uint64_t size_to_read = 0;
    uint32_t read_now = 0;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (unzip->entry_header_read == 0)
        return MZ_PARAM_ERROR;

    size_to_read = unzip->extrafield_local_size - unzip->extrafield_local_pos;

    if (buf == NULL)
        return (int)size_to_read;

    if (len > size_to_read)
        read_now = (uint32_t)size_to_read;
    else
        read_now = len;

    if (read_now == 0)
        return 0;

    if (mz_stream_seek(unzip->stream,
            unzip->extrafield_local_offset + unzip->extrafield_local_pos,
            MZ_STREAM_SEEK_SET) != MZ_OK)
        return MZ_STREAM_ERROR;

    if (mz_stream_read(unzip->stream, buf, read_now) != read_now)
        return MZ_STREAM_ERROR;

    return (int)read_now;
}

extern int ZEXPORT mz_unzip_entry_close(void *handle)
{
    mz_unzip *unzip = NULL;
    uint32_t crc = 0;
    int16_t err = MZ_OK;

    if (handle == NULL)
        return MZ_PARAM_ERROR;
    unzip = (mz_unzip*)handle;

    if (unzip->stream_initialised == 0)
        return MZ_PARAM_ERROR;

#ifdef HAVE_AES
    // AES zip version AE-1 will expect a valid crc as well
    if (unzip->aes_version <= 0x0001)
#endif
    {
        if ((unzip->stream_available == 0) && (unzip->file_info.compression_method != 0))
        {
            crc = mz_stream_crc32_get_value(unzip->crc32_stream);
            if (crc != unzip->file_info.crc)
                err = MZ_CRC_ERROR;
        }
    }

    mz_stream_close(unzip->compress_stream);

    if (unzip->crypt_stream != NULL)
    {
        mz_stream_set_base(unzip->crypt_stream, unzip->stream);
        err = mz_stream_close(unzip->crypt_stream);
        mz_stream_delete(&unzip->crypt_stream);
    }

    mz_stream_delete(&unzip->compress_stream);
    mz_stream_crc32_delete(&unzip->crc32_stream);

    unzip->stream_initialised = 0;

    return err;
}

extern int ZEXPORT mz_unzip_goto_first_entry(void *handle)
{
    mz_unzip *unzip = NULL;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    unzip->num_file = 0;
    unzip->pos_in_central_dir = unzip->offset_central_dir;

    return mz_unzip_entry_read_header(handle);
}

extern int ZEXPORT mz_unzip_goto_next_entry(void *handle)
{
    mz_unzip *unzip = NULL;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (unzip->entry_header_read == 0)
        return MZ_END_OF_LIST;

    if (unzip->global_info.number_entry != UINT16_MAX)
    {
        if (unzip->num_file + 1 == unzip->global_info.number_entry)
            return MZ_END_OF_LIST;
    }

    unzip->num_file += 1;
    unzip->pos_in_central_dir += SIZECENTRALDIRITEM + unzip->file_info.filename_size +
        unzip->file_info.extrafield_size + unzip->file_info.comment_size;

    return mz_unzip_entry_read_header(handle);
}

extern int ZEXPORT mz_unzip_locate_entry(void *handle, const char *filename, mz_filename_compare_cb filename_compare_cb)
{
    mz_unzip *unzip = NULL;
    int16_t err = MZ_OK;

    if (handle == NULL)
        return MZ_PARAM_ERROR;

    unzip = (mz_unzip*)handle;

    if (unzip->entry_header_read == 0)
        return MZ_END_OF_LIST;

    err = mz_unzip_goto_first_entry(handle);

    while (err == MZ_OK)
    {
        if (filename_compare_cb != NULL)
            err = filename_compare_cb(handle, unzip->file_info.filename, filename);
        else
            err = strcmp(unzip->file_info.filename, filename);

        if (err == 0)
            return MZ_OK;

        err = mz_unzip_goto_next_entry(handle);
    }

    return err;
}
