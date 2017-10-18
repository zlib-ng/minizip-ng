/* mz_zip.h -- Zip manipulation
   Version 2.0.1, October 16th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_ZIP_H
#define _MZ_ZIP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ZLIB_H
#  include "zlib.h"
#endif

#include "mz_strm.h"

/***************************************************************************/

typedef struct mz_zip_global_s
{
    uint64_t number_entry;              // total number of entries in the central dir on this disk
    uint32_t number_disk_with_cd;       // number the the disk with central dir, used for spanning ZIP
    uint16_t comment_size;              // size of the global comment of the zip file
    uint8_t  *comment;
} mz_zip_global;

typedef struct mz_zip_file_s
{
    uint16_t version_madeby;            // version made by                 2 bytes
    uint16_t version_needed;            // version needed to extract       2 bytes
    uint16_t flag;                      // general purpose bit flag        2 bytes
    uint16_t compression_method;        // compression method              2 bytes
    uint32_t dos_date;                  // last mod file date in Dos fmt   4 bytes
    uint32_t crc;                       // crc-32                          4 bytes
    uint64_t compressed_size;           // compressed size                 8 bytes
    uint64_t uncompressed_size;         // uncompressed size               8 bytes
    uint16_t filename_size;             // filename length                 2 bytes
    uint16_t extrafield_size;           // extra field length              2 bytes
    uint16_t comment_size;              // file comment length             2 bytes

    uint32_t disk_num_start;            // disk number start               4 bytes
    uint16_t internal_fa;               // internal file attributes        2 bytes
    uint32_t external_fa;               // external file attributes        4 bytes

    uint64_t disk_offset;               // relative offset of local header 8 bytes

    const char     *filename;           // filename string
    const uint8_t  *extrafield;         // extrafield data
    const char     *comment;            // comment string

    uint8_t  zip_64;                    // zip 64 extensions if 1

#ifdef HAVE_AES
    uint16_t aes_version;
    uint8_t  aes_encryption_mode;
#endif
} mz_zip_file;

/***************************************************************************/

extern void* ZEXPORT mz_zip_open(void *stream, int32_t mode);
// Create a zip file
//
//   NOTE: There is no delete function into a zip file. If you want delete file in a zip file, 
//   you must open a zip file, and create another. You can use RAW reading and writing to copy
//   the file you did not want delete.

extern int ZEXPORT mz_zip_get_global_info(void *handle, mz_zip_global **global_info);
// Gets the global zip file info

extern int ZEXPORT mz_zip_entry_write_open(void *handle, const mz_zip_file *file_info,
    int16_t compress_level, const char *password);
// Open a file in the zip for writing

extern int ZEXPORT mz_zip_entry_write(void *handle, const void *buf, uint32_t len);
// Write data in the zip file

extern int ZEXPORT mz_zip_entry_read_open(void *handle, int raw, const char *password);
// Open for reading data the current file in the zip file

extern int ZEXPORT mz_zip_entry_read(void *handle, void *buf, uint32_t len);
// Read bytes from the current file

extern int ZEXPORT mz_zip_entry_close(void *handle);
// Close the current file in the zip file

extern int ZEXPORT mz_zip_entry_get_info(void *handle, mz_zip_file **file_info);
// Get info about the current file
//
//   NOTE: The file info is only valid while the current entry is open

extern int ZEXPORT mz_zip_entry_get_local_info(void *handle, mz_zip_file **local_file_info);
// Get local info about the current file
//
//   NOTE: The local file info is only valid while the current entry is being read

extern int ZEXPORT mz_zip_entry_close_raw(void *handle, uint64_t uncompressed_size, uint32_t crc32);
// Close the current file in the zip file where raw is compressed data

extern int ZEXPORT mz_zip_close(void *handle, const char *global_comment, uint16_t version_madeby);
// Close the zip file
//
//    NOTE: global_comment and version_madeby are only used when the zip file is open for writing

/***************************************************************************/
// Navigate the directory of the zip file

typedef int(*mz_filename_compare_cb)(void *handle, const char *filename1, const char *filename2);

extern int ZEXPORT mz_zip_locate_entry(void *file, const char *filename, mz_filename_compare_cb filename_compare_cb);
// Locate the file with the specified name in the zip file
//
//  if filename_compare_cb == NULL, it uses strcmp
//
//  return MZ_OK if the file is found (it becomes the current file)
//  return MZ_END_OF_LIST if the file is not found 

extern int ZEXPORT mz_zip_goto_first_entry(void *handle);
// Go to the first entry in the zip file 

extern int ZEXPORT mz_zip_goto_next_entry(void *handle);
// Go to the next entry in the zip file or MZ_END_OF_LIST if reaching the end

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _ZIP_H */
