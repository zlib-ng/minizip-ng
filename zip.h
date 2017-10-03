/* zip.h -- IO on .zip files using zlib
   Version 1.2.0, September 16th, 2017
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

#ifndef _ZLIBIOAPI_H
#  include "mzstrm.h"
#endif

#ifdef HAVE_BZIP2
#  include "bzlib.h"
#endif

#define Z_BZIP2ED 12

/***************************************************************************/

#define ZIP_OK                          (0)
#define ZIP_EOF                         (0)
#define ZIP_ERRNO                       (Z_ERRNO)
#define ZIP_PARAMERROR                  (-102)
#define ZIP_BADZIPFILE                  (-103)
#define ZIP_INTERNALERROR               (-104)
    
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
    uint16_t    method;                 // compression method ie Z_DEFLATE
    int         level;                  // compression level
    uint8_t     raw;                    // no compression method if 1
    int         window_bits;            // deflate window bits
    int         mem_level;              // deflate memory level
    int         strategy;               // deflate strategy
} mz_zip_compress;

typedef struct mz_zip_crypt_s
{
#if defined(HAVE_AES)
    uint8_t     aes;                    // enable winzip aes encryption if 1
#endif
    uint32_t    crc_for_crypting;       // crc to use for traditional encryption
    const char *password;               // encryption password
} mz_zip_crypt;

/***************************************************************************/

#define MZ_APPEND_STATUS_CREATE        (0)  // create new zip
#define MZ_APPEND_STATUS_CREATEAFTER   (1)  // create zip after file
#define MZ_APPEND_STATUS_ADDINZIP      (2)  // add existing files to zip

/***************************************************************************/

// Create a zipfile
extern void* ZEXPORT mz_zip_open(const char *path, int append, uint64_t disk_size, 
    const char **globalcomment, void *stream);

// Open a file in the ZIP for writing
extern int ZEXPORT mz_zip_entry_open(void *handle, const mz_zip_file *file_info, 
    const mz_zip_compress *compress_info, const mz_zip_crypt *crypt_info);

// Write data in the zipfile
extern int ZEXPORT mz_zip_entry_write(void *handle, const void *buf, uint32_t len);

// Close the current file in the zipfile
extern int ZEXPORT mz_zip_entry_close(void *handle);

// Close the current file in the zipfile where raw is compressed data
extern int ZEXPORT mz_zip_entry_close_raw(void *handle, uint64_t uncompressed_size, uint32_t crc32);

// Close the zipfile
extern int ZEXPORT mz_zip_close(void *handle, const char *global_comment, uint16_t version_madeby);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif /* _ZIP_H */
