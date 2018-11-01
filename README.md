# minizip 2.7.1

minizip is a zip manipulation library written in C that is supported on Windows, macOS, and Linux. 

[![License: Zlib](https://img.shields.io/badge/license-zlib-lightgrey.svg)](https://github.com/nmoinvaz/minizip/blob/master/LICENSE)

Maintained by Nathan Moinvaziri.

## Fork Motivation and History

This library is a complete refactoring of the minizip contribution found in the zlib
distribution. The motivation for this fork has been the inclusion of advanced features, 
improvements in code maintainability and readability, and the reduction of duplicate code.

Minizip was originally developed by [Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html) and 
had been contributed to by many people. As part of the zlib distribution, Mark Adler has maintained the
original [minizip](https://github.com/madler/zlib/tree/master/contrib/minizip) project.

In 2006, I began working with the minizip project and started submitting bugs I found in the library to 
Gilles Vollant via e-mail. In 2010, I implemented some additional features like disk splitting, 
I/O buffering, and AES encryption. My continued work on the project necessitated setting up a public 
repository so I could share these and other improvements with the rest of the world. I have been maintaining 
and actively developing this fork of the project ever since. In 2017, I refactored and rewrote most of 
library as it had become difficult to maintain and code readability had suffered over the years.

Dev: [![Dev Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=dev)](https://travis-ci.org/nmoinvaz/minizip/branches)
Master: [![Master Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=master)](https://travis-ci.org/nmoinvaz/minizip/branches)

## Features

+ Creating and extracting zip archives.
+ Adding and removing entries from zip archives.
+ Read and write raw zip entry data.
+ Reading and writing zip archives from memory.
+ Zlib, BZIP2, and LZMA compression methods.
+ Password protection through Traditional PKWARE and [WinZIP AES](https://www.winzip.com/aes_info.htm) encryption.
+ Buffered streaming for improved I/O performance.
+ NTFS timestamp support for UTC last modified, last accessed, and creation dates.
+ Disk split support for splitting zip archives into multiple files.
+ Preservation of file attributes across file systems.
+ Unicode filename support through UTF-8 encoding.
+ IBM Codepage 437 legacy character encoding support.
+ Turn off compilation of compression, decompression, or encryption.
+ Windows (Win32 & WinRT), macOS and Linux platform support.
+ Streaming interface for easy implementation of additional platforms.
+ Support for Apple's compression library ZLIB implementation.
+ Zero out local file header information.
+ Zip/unzip of central directory to reduce size.
+ Ability to generate and verify CMS signature for each entry.
+ Compatibility interface for older versions of minizip.
+ Example minizip command line tool.

## Build

To generate project files for your platform:

1. [Download and install](https://cmake.org/install/) cmake.
2. Run cmake in the minizip directory.

```
cmake . -DBUILD_TEST=ON
cmake --build .
```

## Build Options

| Name | Description | Default Value |
|:- |:-|:-:|
| USE_COMPAT | Enables compatibility layer | ON |
| USE_ZLIB | Enables ZLIB compression | ON |
| USE_BZIP2 | Enables BZIP2 compression | ON |
| USE_LZMA | Enables LZMA compression | ON |
| USE_PKCRYPT | Enables PKWARE traditional encryption | ON |
| USE_AES | Enables WinZIP AES encryption | ON |
| USE_LIBCOMP | Enables Apple compression | OFF |
| USE_OPENSSL | Enables OpenSSL encryption | OFF |
| COMPRESS_ONLY | Only support compression | OFF |
| DECOMPRESS_ONLY | Only support decompression | OFF |
| BUILD_TEST | Builds minizip test executable | OFF |

## Contents

| File(s) | Description | Required |
|:- |:-|:-:|
| minizip.c | Sample application | No |
| mz_compat.\* | Minizip 1.0 compatibility layer | No |
| mz.h | Error codes and flags | Yes |
| mz_os\* | Platform specific file/utility functions | Likely |
| mz_crypt\* | Configuration specific crypto/hashing functions | Encryption, Signing |
| mz_strm.\* | Stream interface | Yes |
| mz_strm_buf.\* | Buffered stream | No |
| mz_strm_bzip.\* | BZIP2 stream using libbzip2 | No |
| mz_strm_crc32.\* | CRC32 stream | Yes |
| mz_strm_libcomp.\* | Apple compression stream | No |
| mz_strm_lzma.\* | LZMA stream using liblzma | zlib or liblzma |
| mz_strm_mem.\* | Memory stream | Yes |
| mz_strm_split.\* | Disk splitting stream | No |
| mz_strm_pkcrypt.\* | PKWARE traditional encryption stream | No |
| mz_strm_os\* | Platform specific file stream | Yes |
| mz_strm_wzaes.\* | WinZIP AES stream | No |
| mz_strm_zlib.\* | Deflate stream using zlib | zlib or liblzma |
| mz_zip.\* | Zip format | Yes |
| mz_zip_rw.\* | Zip reader/writer | No |

## Third-Party Libraries

+ [zlib](https://zlib.net/) written by Mark Adler and Jean-loup Gailly.
  + Not included in this repository
  + Or alternatively, [zlib-ng](https://github.com/Dead2/zlib-ng) by Hans Kristian Rosbach
+ [BZIP2](https://www.sourceware.org/bzip2/) written by Julian Seward.
+ [liblzma](https://tukaani.org/xz/) written by Lasse Collin.
  + Modifications were made to support the ZIP file format specification
+ [AES](https://github.com/BrianGladman/aes) and [SHA](https://github.com/BrianGladman/sha) libraries of Brian Gladman.

## Acknowledgments

Thanks to [Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html) on which this work is originally based on. 

Thanks go out to all the people who have taken the time to contribute code reviews, testing and/or patches. This project would not have been nearly as good without you.

The [ZIP format](https://github.com/nmoinvaz/minizip/blob/master/doc/appnote.txt) was defined by Phil Katz of PKWARE.
