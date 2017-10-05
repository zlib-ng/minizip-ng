/* mz_compat.h -- Backwards compatible interface for older versions of MiniZip
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

#ifndef _MZ_COMPAT_H
#define _MZ_COMPAT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#include "zlib.h"
#ifdef __GNUC__
#  define ZIP_UNUSED __attribute__((__unused__))
#else
#  define ZIP_UNUSED
#endif
    
#ifndef DEF_MEM_LEVEL
#  if MAX_MEM_LEVEL >= 8
#    define DEF_MEM_LEVEL 8
#  else
#    define DEF_MEM_LEVEL  MAX_MEM_LEVEL
#  endif
#endif

#if defined(STRICTZIP) || defined(STRICTZIPUNZIP)
/* like the STRICT of WIN32, we define a pointer that cannot be converted
    from (void*) without cast */
typedef struct TagzipFile__ { int unused; } zip_file__;
typedef zip_file__ *zipFile;
#else
typedef voidp zipFile;
#endif

typedef struct
{
    uint32_t    dos_date;
    uint16_t    internal_fa;        /* internal file attributes        2 bytes */
    uint32_t    external_fa;        /* external file attributes        4 bytes */
} zip_fileinfo;

#define ZIP_OK                          (0)
#define ZIP_EOF                         (0)
#define ZIP_ERRNO                       (Z_ERRNO)
#define ZIP_PARAMERROR                  (-102)
#define ZIP_BADZIPFILE                  (-103)
#define ZIP_INTERNALERROR               (-104)

#define APPEND_STATUS_CREATE        (MZ_OPENMODE_CREATE)
#define APPEND_STATUS_CREATEAFTER   (MZ_OPENMODE_CREATEAFTER)
#define APPEND_STATUS_ADDINZIP      (MZ_OPENMODE_ADDINZIP)

extern zipFile ZEXPORT zipOpen(const char *path, int append, voidpf stream);
/* Create a zipfile.

   path should contain the full path (by example, on a Windows XP computer 
      "c:\\zlib\\zlib113.zip" or on an Unix computer "zlib/zlib113.zip". 

   return NULL if zipfile cannot be opened
   return zipFile handle if no error

   If the file path exist and append == APPEND_STATUS_CREATEAFTER, the zip
   will be created at the end of the file. (useful if the file contain a self extractor code)
   If the file path exist and append == APPEND_STATUS_ADDINZIP, we will add files in existing 
   zip (be sure you don't add file that doesn't exist)

   NOTE: There is no delete function into a zipfile. If you want delete file into a zipfile, 
   you must open a zipfile, and create another. Of course, you can use RAW reading and writing to copy
   the file you did not want delete. */

extern zipFile ZEXPORT zipOpen2(const char *path, int append, const char **globalcomment, 
    voidpf stream);

extern zipFile ZEXPORT zipOpen3(const char *path, int append, uint64_t disk_size, 
    const char **globalcomment,  voidpf stream);
/* Same as zipOpen2 but allows specification of spanned zip size */

extern int ZEXPORT zipOpenNewFileInZip(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global, 
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level);
/* Open a file in the ZIP for writing.

   filename : the filename in zip (if NULL, '-' without quote will be used
   *zipfi contain supplemental information
   extrafield_local buffer to store the local header extra field data, can be NULL
   size_extrafield_local size of extrafield_local buffer
   extrafield_global buffer to store the global header extra field data, can be NULL
   size_extrafield_global size of extrafield_local buffer
   comment buffer for comment string
   method contain the compression method (0 for store, Z_DEFLATED for deflate)
   level contain the level of compression (can be Z_DEFAULT_COMPRESSION)
   zip64 is set to 1 if a zip64 extended information block should be added to the local file header.
   this MUST be '1' if the uncompressed size is >= 0xffffffff. */

extern int ZEXPORT zipOpenNewFileInZip64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int zip64);
/* Same as zipOpenNewFileInZip with zip64 support */

extern int ZEXPORT zipOpenNewFileInZip2(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw);
/* Same as zipOpenNewFileInZip, except if raw=1, we write raw file */

extern int ZEXPORT zipOpenNewFileInZip2_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int zip64);
/* Same as zipOpenNewFileInZip3 with zip64 support */

extern int ZEXPORT zipOpenNewFileInZip3(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting);
/* Same as zipOpenNewFileInZip2, except
    windowBits, memLevel, strategy : see parameter strategy in deflateInit2
    password : crypting password (NULL for no crypting)
    crc_for_crypting : crc of file to compress (needed for crypting) */

extern int ZEXPORT zipOpenNewFileInZip3_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, int zip64);
/* Same as zipOpenNewFileInZip3 with zip64 support */

extern int ZEXPORT zipOpenNewFileInZip4(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base);
/* Same as zipOpenNewFileInZip3 except versionMadeBy & flag fields */

extern int ZEXPORT zipOpenNewFileInZip4_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base, int zip64);
/* Same as zipOpenNewFileInZip4 with zip64 support */

extern int ZEXPORT zipWriteInFileInZip(zipFile file, const void *buf, uint32_t len);
/* Write data in the zipfile */

extern int ZEXPORT zipCloseFileInZip(zipFile file);
/* Close the current file in the zipfile */

extern int ZEXPORT zipCloseFileInZipRaw(zipFile file, uint32_t uncompressed_size, uint32_t crc32);
/* Close the current file in the zipfile, for file opened with parameter raw=1 in zipOpenNewFileInZip2
   where raw is compressed data. Parameters uncompressed_size and crc32 are value for the uncompressed data. */

extern int ZEXPORT zipClose(zipFile file, const char *global_comment);
/* Close the zipfile */

extern int ZEXPORT zipClose_64(zipFile file, const char *global_comment);

extern int ZEXPORT zipClose2_64(zipFile file, const char *global_comment, uint16_t version_madeby);
/* Same as zipClose_64 except version_madeby field */

#if defined(STRICTUNZIP) || defined(STRICTZIPUNZIP)
/* like the STRICT of WIN32, we define a pointer that cannot be converted
    from (void*) without cast */
typedef struct TagunzFile__ { int unused; } unz_file__;
typedef unz_file__ *unzFile;
#else
typedef voidp unzFile;
#endif
#define ZIP_OK                          (0)
#define ZIP_EOF                         (0)
#define ZIP_ERRNO                       (Z_ERRNO)
#define ZIP_PARAMERROR                  (-102)
#define ZIP_BADZIPFILE                  (-103)
#define ZIP_INTERNALERROR               (-104)

#define UNZ_OK                          (0)
#define UNZ_END_OF_LIST_OF_FILE         (-100)
#define UNZ_ERRNO                       (Z_ERRNO)
#define UNZ_EOF                         (0)
#define UNZ_PARAMERROR                  (-102)
#define UNZ_BADZIPFILE                  (-103)
#define UNZ_INTERNALERROR               (-104)
#define UNZ_CRCERROR                    (-105)
#define UNZ_BADPASSWORD                 (-106)

/* unz_global_info structure contain global data about the ZIPfile
   These data comes from the end of central dir */
typedef struct unz_global_info64_s
{
    uint64_t number_entry;          /* total number of entries in the central dir on this disk */
    uint32_t number_disk_with_CD;   /* number the the disk with central dir, used for spanning ZIP*/
    uint16_t size_comment;          /* size of the global comment of the zipfile */
} unz_global_info64;

typedef struct unz_global_info_s
{
    uint32_t number_entry;          /* total number of entries in the central dir on this disk */
    uint32_t number_disk_with_CD;   /* number the the disk with central dir, used for spanning ZIP*/
    uint16_t size_comment;          /* size of the global comment of the zipfile */
} unz_global_info;

/* unz_file_info contain information about a file in the zipfile */
typedef struct unz_file_info64_s
{
    uint16_t version;               /* version made by                 2 bytes */
    uint16_t version_needed;        /* version needed to extract       2 bytes */
    uint16_t flag;                  /* general purpose bit flag        2 bytes */
    uint16_t compression_method;    /* compression method              2 bytes */
    uint32_t dos_date;              /* last mod file date in Dos fmt   4 bytes */
    uint32_t crc;                   /* crc-32                          4 bytes */
    uint64_t compressed_size;       /* compressed size                 8 bytes */
    uint64_t uncompressed_size;     /* uncompressed size               8 bytes */
    uint16_t size_filename;         /* filename length                 2 bytes */
    uint16_t size_file_extra;       /* extra field length              2 bytes */
    uint16_t size_file_comment;     /* file comment length             2 bytes */

    uint32_t disk_num_start;        /* disk number start               4 bytes */
    uint16_t internal_fa;           /* internal file attributes        2 bytes */
    uint32_t external_fa;           /* external file attributes        4 bytes */

    uint64_t disk_offset;

    uint16_t size_file_extra_internal;
} unz_file_info64;

typedef struct unz_file_info_s
{
    uint16_t version;               /* version made by                 2 bytes */
    uint16_t version_needed;        /* version needed to extract       2 bytes */
    uint16_t flag;                  /* general purpose bit flag        2 bytes */
    uint16_t compression_method;    /* compression method              2 bytes */
    uint32_t dos_date;              /* last mod file date in Dos fmt   4 bytes */
    uint32_t crc;                   /* crc-32                          4 bytes */
    uint32_t compressed_size;       /* compressed size                 4 bytes */
    uint32_t uncompressed_size;     /* uncompressed size               4 bytes */
    uint16_t size_filename;         /* filename length                 2 bytes */
    uint16_t size_file_extra;       /* extra field length              2 bytes */
    uint16_t size_file_comment;     /* file comment length             2 bytes */

    uint16_t disk_num_start;        /* disk number start               2 bytes */
    uint16_t internal_fa;           /* internal file attributes        2 bytes */
    uint32_t external_fa;           /* external file attributes        4 bytes */

    uint64_t disk_offset;
} unz_file_info;

extern unzFile ZEXPORT unzOpen(const char *path, void *stream);
/* Open a Zip file.

   path should contain the full path (by example, on a Windows XP computer 
      "c:\\zlib\\zlib113.zip" or on an Unix computer "zlib/zlib113.zip". 
   return NULL if zipfile cannot be opened or doesn't exist
   return unzFile handle if no error

   NOTE: The "64" function take a const void *pointer, because  the path is just the value passed to the
   open64_file_func callback. Under Windows, if UNICODE is defined, using fill_fopen64_filefunc, the path 
   is a pointer to a wide unicode string  (LPCTSTR is LPCWSTR), so const char *does not describe the reality */

extern int ZEXPORT unzClose(unzFile file);
/* Close a ZipFile opened with unzOpen. If there is files inside the .Zip opened with unzOpenCurrentFile,
   these files MUST be closed with unzipCloseCurrentFile before call unzipClose.

   return UNZ_OK if there is no error */

extern int ZEXPORT unzGetGlobalInfo(unzFile file, unz_global_info *pglobal_info);
extern int ZEXPORT unzGetGlobalInfo64(unzFile file, unz_global_info64 *pglobal_info);
/* Write info about the ZipFile in the *pglobal_info structure.

   return UNZ_OK if no error */

extern int ZEXPORT unzGetGlobalComment(unzFile file, char *comment, uint16_t comment_size);
/* Get the global comment string of the ZipFile, in the comment buffer.

   uSizeBuf is the size of the szComment buffer.
   return the number of byte copied or an error code <0 */

/***************************************************************************/
/* Reading the content of the current zipfile, you can open it, read data from it, and close it
   (you can close it before reading all the file) */

extern int ZEXPORT unzOpenCurrentFile(unzFile file);
/* Open for reading data the current file in the zipfile.

   return UNZ_OK if no error */

extern int ZEXPORT unzOpenCurrentFilePassword(unzFile file, const char *password);
/* Open for reading data the current file in the zipfile.
   password is a crypting password

   return UNZ_OK if no error */

extern int ZEXPORT unzOpenCurrentFile2(unzFile file, int *method, int *level, int raw);
/* Same as unzOpenCurrentFile, but open for read raw the file (not uncompress)
   if raw==1 *method will receive method of compression, *level will receive level of compression

   NOTE: you can set level parameter as NULL (if you did not want known level,
         but you CANNOT set method parameter as NULL */

extern int ZEXPORT unzOpenCurrentFile3(unzFile file, int *method, int *level, int raw, const char *password);
/* Same as unzOpenCurrentFile, but takes extra parameter password for encrypted files */

extern int ZEXPORT unzReadCurrentFile(unzFile file, voidp buf, uint32_t len);
/* Read bytes from the current file (opened by unzOpenCurrentFile)
   buf contain buffer where data must be copied
   len the size of buf.

   return the number of byte copied if somes bytes are copied
   return 0 if the end of file was reached
   return <0 with error code if there is an error (UNZ_ERRNO for IO error, or zLib error for uncompress error) */

extern int ZEXPORT unzGetCurrentFileInfo(unzFile file, unz_file_info *pfile_info, char *filename, 
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size);
extern int ZEXPORT unzGetCurrentFileInfo64(unzFile file, unz_file_info64 *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size);
/* Get Info about the current file

   pfile_info if != NULL, the *pfile_info structure will contain somes info about the current file
   filename if != NULL, the file name string will be copied in filename 
   filename_size is the size of the filename buffer
   extrafield if != NULL, the extra field information from the central header will be copied in to
   extrafield_size is the size of the extraField buffer 
   comment if != NULL, the comment string of the file will be copied in to
   comment_size is the size of the comment buffer */

extern int ZEXPORT unzGetLocalExtrafield(unzFile file, voidp buf, uint32_t len);
/* Read extra field from the current file (opened by unzOpenCurrentFile)
   This is the local-header version of the extra field (sometimes, there is
   more info in the local-header version than in the central-header)

   if buf == NULL, it return the size of the local extra field
   if buf != NULL, len is the size of the buffer, the extra header is copied in buf.

   return number of bytes copied in buf, or (if <0) the error code */

extern int ZEXPORT unzCloseCurrentFile(unzFile file);
/* Close the file in zip opened with unzOpenCurrentFile

   return UNZ_CRCERROR if all the file was read but the CRC is not good */

/***************************************************************************/
/* Browse the directory of the zipfile */

typedef int (*unzFileNameComparer)(unzFile file, const char *filename1, const char *filename2);
typedef int (*unzIteratorFunction)(unzFile file);
typedef int (*unzIteratorFunction2)(unzFile file, unz_file_info64 *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size);

extern int ZEXPORT unzGoToFirstFile(unzFile file);
/* Set the current file of the zipfile to the first file.

   return UNZ_OK if no error */

extern int ZEXPORT unzGoToFirstFile2(unzFile file, unz_file_info64 *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size);
/* Set the current file of the zipfile to the first file and retrieves the current info on success. 
   Not as seek intensive as unzGoToFirstFile + unzGetCurrentFileInfo.

   return UNZ_OK if no error */

extern int ZEXPORT unzGoToNextFile(unzFile file);
/* Set the current file of the zipfile to the next file.

   return UNZ_OK if no error
   return UNZ_END_OF_LIST_OF_FILE if the actual file was the latest */

extern int ZEXPORT unzGoToNextFile2(unzFile file, unz_file_info64 *pfile_info, char *filename,
    uint16_t filename_size, void *extrafield, uint16_t extrafield_size, char *comment, uint16_t comment_size);
/* Set the current file of the zipfile to the next file and retrieves the current 
   info on success. Does less seeking around than unzGotoNextFile + unzGetCurrentFileInfo.

   return UNZ_OK if no error
   return UNZ_END_OF_LIST_OF_FILE if the actual file was the latest */

extern int ZEXPORT unzLocateFile(unzFile file, const char *filename, unzFileNameComparer filename_compare_func);
/* Try locate the file szFileName in the zipfile. For custom filename comparison pass in comparison function.

   return UNZ_OK if the file is found (it becomes the current file)
   return UNZ_END_OF_LIST_OF_FILE if the file is not found */

#ifdef __cplusplus
}
#endif

#endif
