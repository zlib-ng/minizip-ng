/* mz_zip.h -- Zip manipulation
   Version 2.0.0, October 4th, 2017
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

#ifndef MZ_METHOD
#  define MZ_METHOD_RAW                 (0)
#  define MZ_METHOD_DEFLATE             (8)
#  define MZ_METHOD_BZIP2               (12)
#  define MZ_METHOD_LZMA                (14)
#endif

#define MZ_COMPRESS_LEVEL_DEFAULT       (-1)
#define MZ_COMPRESS_WINDOW_BITS_DEFAULT (0)
#define MZ_COMPRESS_MEM_LEVEL_DEFAULT   (0)
#define MZ_COMPRESS_STRATEGY_DEFAULT    (-1)

/***************************************************************************/

typedef struct mz_zip_file_s
{
    uint32_t    dos_date;               // ms-dos date and time
    uint16_t    internal_fa;            // internal file attributes
    uint32_t    external_fa;            // external file attributes
    const uint8_t *extrafield_local;    // extra fields in local header
    uint16_t    extrafield_local_size;  // size of additional extra fields in local header
    const uint8_t *extrafield_global;   // extra fields in global header
    uint16_t    extrafield_global_size; // size of extra fields in global header
    uint16_t    version_madeby;         // version made by
    const char  *comment;               // file comment
    const char  *filename;              // filename
    uint8_t     zip64;                  // enable zip64 extensions if 1
    uint16_t    flag;                   // base flag value
} mz_zip_file;

typedef struct mz_zip_compress_s
{
    uint16_t    method;                 // compression method
    int         level;                  // compression level
    int         window_bits;            // deflate window bits
    int         mem_level;              // deflate memory level
    int         strategy;               // deflate strategy
} mz_zip_compress;

typedef struct mz_zip_crypt_s
{
    const char *password;               // encryption password
#if defined(HAVE_AES)
    uint8_t     aes;                    // enable winzip aes encryption if 1
#endif
} mz_zip_crypt;

/***************************************************************************/

extern void* ZEXPORT mz_zip_open(uint8_t open_existing, uint64_t disk_size, void *stream);
// Create a zip file
//
//   NOTE: There is no delete function into a zip file. If you want delete file in a zip file, 
//   you must open a zip file, and create another. You can use RAW reading and writing to copy
//   the file you did not want delete.

extern int ZEXPORT mz_zip_get_global_comment(void *handle, const char **global_comment);
// Gets the global comments if opening an existing zip

extern int ZEXPORT mz_zip_entry_open(void *handle, const mz_zip_file *file_info, 
    const mz_zip_compress *compress_info, const mz_zip_crypt *crypt_info);
// Open a file in the ZIP for writing

extern int ZEXPORT mz_zip_entry_write(void *handle, const void *buf, uint32_t len);
// Write data in the zip file

extern int ZEXPORT mz_zip_entry_close(void *handle);
// Close the current file in the zip file

extern int ZEXPORT mz_zip_entry_close_raw(void *handle, uint64_t uncompressed_size, uint32_t crc32);
// Close the current file in the zip file where raw is compressed data

extern int ZEXPORT mz_zip_close(void *handle, const char *global_comment, uint16_t version_madeby);
// Close the zip file

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _ZIP_H */
