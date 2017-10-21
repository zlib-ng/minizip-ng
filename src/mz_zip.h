/* mz_zip.h -- Zip manipulation
   Version 2.1.1, October 21st, 2017
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

#ifdef HAVE_AES
    uint16_t aes_version;               // winzip aes extension if not 0
    uint8_t  aes_encryption_mode;       // winzip aes encryption mode
#endif
} mz_zip_file;

/***************************************************************************/

extern void * ZEXPORT mz_zip_open(void *stream, int32_t mode);
// Create a zip file
//
// NOTE: There is no delete function into a zip file. If you want delete file in a 
// zip file, you must open a zip file, and create another. You can use RAW reading
// and writing to copy the file you did not want delete.

extern int32_t ZEXPORT mz_zip_close(void *handle);
// Close the zip file

extern int32_t ZEXPORT mz_zip_get_comment(void *handle, const char **comment);
// Get a pointer to the global comment

extern int32_t ZEXPORT mz_zip_set_comment(void *handle, const char *comment);
// Set the global comment used for writing zip file

extern int32_t ZEXPORT mz_zip_get_version_madeby(void *handle, uint16_t *version_madeby);
// Get the version made by

extern int32_t ZEXPORT mz_zip_set_version_madeby(void *handle, uint16_t version_madeby);
// Set the version made by used for writing zip file

extern int32_t ZEXPORT mz_zip_entry_write_open(void *handle, const mz_zip_file *file_info,
    int16_t compress_level, const char *password);
// Open for writing the current file in the zip file

extern int32_t ZEXPORT mz_zip_entry_write(void *handle, const void *buf, uint32_t len);
// Write bytes from the current file in the zip file

extern int32_t ZEXPORT mz_zip_entry_read_open(void *handle, int16_t raw, const char *password);
// Open for reading the current file in the zip file

extern int32_t ZEXPORT mz_zip_entry_read(void *handle, void *buf, uint32_t len);
// Read bytes from the current file in the zip file

extern int32_t ZEXPORT mz_zip_entry_get_info(void *handle, mz_zip_file **file_info);
// Get info about the current file
//
// NOTE: The file info is only valid while the current entry is open.

extern int32_t ZEXPORT mz_zip_entry_get_local_info(void *handle, mz_zip_file **local_file_info);
// Get local info about the current file
//
// NOTE: The local file info is only valid while the current entry is being read.

extern int32_t ZEXPORT mz_zip_entry_close_raw(void *handle, uint64_t uncompressed_size, uint32_t crc32);
// Close the current file in the zip file where raw is compressed data

extern int32_t ZEXPORT mz_zip_entry_close(void *handle);
// Close the current file in the zip file

/***************************************************************************/

extern int32_t ZEXPORT mz_zip_get_number_entry(void *handle, int64_t *number_entry);
// Get the total number of entries

extern int32_t ZEXPORT mz_zip_goto_first_entry(void *handle);
// Go to the first entry in the zip file 

extern int32_t ZEXPORT mz_zip_goto_next_entry(void *handle);
// Go to the next entry in the zip file or MZ_END_OF_LIST if reaching the end

typedef int32_t (*mz_filename_compare_cb)(void *handle, const char *filename1, const char *filename2);

extern int32_t ZEXPORT mz_zip_locate_entry(void *handle, const char *filename, mz_filename_compare_cb filename_compare_cb);
// Locate the file with the specified name in the zip file
//
// NOTE: if filename_compare_cb == NULL, it uses strcmp
//
// return MZ_OK if the file is found (it becomes the current file)
// return MZ_END_OF_LIST if the file is not found 

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _ZIP_H */
