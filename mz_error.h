/* mz_error.h -- List of function return codes
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef _MZ_ERROR_H
#define _MZ_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#define MZ_OK                         (0)
#define MZ_EOF                        (MZ_OK)
#define MZ_STREAM_ERROR               (-1)
#define MZ_END_OF_LIST                (-100)
#define MZ_PARAM_ERROR                (-102)
#define MZ_FORMAT_ERROR               (-103)
#define MZ_INTERNAL_ERROR             (-104)
#define MZ_CRC_ERROR                  (-105)
#define MZ_CRYPT_ERROR                (-106)
#define MZ_EXIST_ERROR                (-107)

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
