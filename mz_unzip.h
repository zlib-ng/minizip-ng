/* mz_unzip.h -- Zip manipulation
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
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

#ifndef _MZ_UNZIP_H
#define _MZ_UNZIP_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _ZLIB_H
#include "zlib.h"
#endif

#include "mz_strm.h"

/***************************************************************************/

#ifndef MZ_METHOD
#  define MZ_METHOD_RAW                 (0)
#  define MZ_METHOD_DEFLATE             (8)
#  define MZ_METHOD_BZIP2               (12)
#  define MZ_METHOD_LZMA                (14)
#endif

/***************************************************************************/

// Global data about the zip file that come from the end of central dir
typedef struct mz_unzip_global_s
{
    uint64_t number_entry;          // total number of entries in the central dir on this disk
    uint32_t number_disk_with_CD;   // number the the disk with central dir, used for spanning ZIP
    uint16_t comment_size;          // size of the global comment of the zip file
} mz_unzip_global;

// Info about a file in the zip file at the central directory
typedef struct mz_unzip_file_s
{
    uint16_t version;               // version made by                 2 bytes
    uint16_t version_needed;        // version needed to extract       2 bytes
    uint16_t flag;                  // general purpose bit flag        2 bytes
    uint16_t compression_method;    // compression method              2 bytes
    uint32_t dos_date;              // last mod file date in Dos fmt   4 bytes
    uint32_t crc;                   // crc-32                          4 bytes
    uint64_t compressed_size;       // compressed size                 8 bytes
    uint64_t uncompressed_size;     // uncompressed size               8 bytes
    uint16_t filename_size;         // filename length                 2 bytes
    uint16_t extrafield_size;       // extra field length              2 bytes
    uint16_t comment_size;          // file comment length             2 bytes

    uint32_t disk_num_start;        // disk number start               4 bytes
    uint16_t internal_fa;           // internal file attributes        2 bytes
    uint32_t external_fa;           // external file attributes        4 bytes

    uint64_t disk_offset;           // relative offset of local header 8 bytes

    char     *filename;             // filename string
    uint8_t  *extrafield;           // extrafield data
    char     *comment;              // comment string
} mz_unzip_file;

/***************************************************************************/
// Opening and close a zip file

// Open a zip file
extern void* ZEXPORT mz_unzip_open(void *stream);

// Close a zip file
extern int ZEXPORT mz_unzip_close(void *handle);

// Get global info about the zip file 
extern int ZEXPORT mz_unzip_get_global_info(void *handle, mz_unzip_global *global_info);

// Get the global comment string of the zip file, in the comment buffer 
extern int ZEXPORT mz_unzip_get_global_comment(void *handle, char *comment, uint16_t comment_size);

/***************************************************************************/
// Reading the content of the current zip file, you can open it, read it, and close it

extern int ZEXPORT mz_unzip_entry_open(void *handle, int raw, const char *password);
// Open for reading data the current file in the zip file

extern int ZEXPORT mz_unzip_entry_read(void *handle, void *buf, uint32_t len);
// Read bytes from the current file

extern int ZEXPORT mz_unzip_entry_get_info(void *handle, mz_unzip_file **file_info);
// Get info about the current file

extern int ZEXPORT mz_unzip_entry_get_extrafield_local(void *handle, void *buf, uint32_t len);
// Read extra field from the current file
//
//   This is the local-header version of the extra field (sometimes, there is
//   more info in the local-header version than in the central-header)
//
//   if buf == NULL, it return the size of the local extra field
//   if buf != NULL, len is the size of the buffer, the extra header is copied in buf.
//
//   return number of bytes copied in buf, or (if <0) the error code 

extern int ZEXPORT mz_unzip_entry_close(void *handle);
// Close the file in zip

/***************************************************************************/
// Navigate the directory of the zip file

typedef int (*mz_filename_compare_cb)(void *handle, const char *filename1, const char *filename2);

extern int ZEXPORT mz_unzip_locate_entry(void *file, const char *filename, mz_filename_compare_cb filename_compare_cb);
// Locate the file with the specified name in the zip file
//
//  if filename_compare_cb == NULL, it uses strcmp
//
//  return MZ_OK if the file is found (it becomes the current file)
//  return MZ_END_OF_LIST if the file is not found 

extern int ZEXPORT mz_unzip_goto_first_entry(void *handle);
// Go to the first entry in the zip file 

extern int ZEXPORT mz_unzip_goto_next_entry(void *handle);
// Go to the next entry in the zip file or MZ_END_OF_LIST if reaching the end

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _UNZ_H */
