/* mz.h -- Errors codes, zip flags and magic
   Version 2.2.0, October 22nd, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_H
#define _MZ_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

// MZ_ERROR
#define MZ_OK                           (0)
#define MZ_STREAM_ERROR                 (-1)
#define MZ_DATA_ERROR                   (-3)
#define MZ_MEM_ERROR                    (-4)
#define MZ_END_OF_LIST                  (-100)
#define MZ_END_OF_STREAM                (-101)
#define MZ_PARAM_ERROR                  (-102)
#define MZ_FORMAT_ERROR                 (-103)
#define MZ_INTERNAL_ERROR               (-104)
#define MZ_CRC_ERROR                    (-105)
#define MZ_CRYPT_ERROR                  (-106)
#define MZ_EXIST_ERROR                  (-107)

// MZ_COMPRESS_METHOD
#define MZ_COMPRESS_METHOD_RAW          (0)
#define MZ_COMPRESS_METHOD_DEFLATE      (8)
#define MZ_COMPRESS_METHOD_BZIP2        (12)
#define MZ_COMPRESS_METHOD_LZMA         (14)
#define MZ_COMPRESS_METHOD_AES          (99)

// MZ_COMPRESS_OPTIONS
#define MZ_COMPRESS_LEVEL_DEFAULT       (-1)
#define MZ_COMPRESS_WINDOW_BITS_DEFAULT (0)
#define MZ_COMPRESS_MEM_LEVEL_DEFAULT   (0)
#define MZ_COMPRESS_STRATEGY_DEFAULT    (-1)

// MZ_ZIP_FLAG
#define MZ_ZIP_FLAG_ENCRYPTED           (1 << 0)
#define MZ_ZIP_FLAG_LZMA_EOS_MARKER     (1 << 1)
#define MZ_ZIP_FLAG_DEFLATE_MAX         (1 << 1)
#define MZ_ZIP_FLAG_DEFLATE_NORMAL      (0)
#define MZ_ZIP_FLAG_DEFLATE_FAST        (1 << 2)
#define MZ_ZIP_FLAG_DEFLATE_SUPER_FAST  (MZ_ZIP_FLAG_DEFLATE_FAST | \
                                         MZ_ZIP_FLAG_DEFLATE_MAX)
#define MZ_ZIP_FLAG_DATA_DESCRIPTOR     (1 << 3)

// MZ_AES
#define MZ_AES_VERSION                  (1)
#define MZ_AES_ENCRYPTION_MODE_128      (0x01)
#define MZ_AES_ENCRYPTION_MODE_192      (0x02)
#define MZ_AES_ENCRYPTION_MODE_256      (0x03)

// MZ_VERSION
#define MZ_VERSION                      ("2.2.0")

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
