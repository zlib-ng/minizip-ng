# minizip 2.8.4

minizip is a zip manipulation library written in C that is supported on Windows, macOS, and Linux. 

[![License: Zlib](https://img.shields.io/badge/license-zlib-lightgrey.svg)](https://github.com/nmoinvaz/minizip/blob/master/LICENSE)
[![Code Quality: Cpp](https://img.shields.io/lgtm/grade/cpp/g/nmoinvaz/minizip.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/nmoinvaz/minizip/context:cpp)

Maintained by Nathan Moinvaziri.

## Branches

| Name | State | Version | Description |
|:- |:-:|:-:|:-|
|[master](https://github.com/nmoinvaz/minizip/tree/master)|Active [![Master Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=master)](https://travis-ci.org/nmoinvaz/minizip/branches)|2.x|Modern rewrite of 1.2 branch that includes more advanced features, improvements in code maintainability and readability, and the reduction of duplicate code. Compatibility layer provided for older versions.|
|[dev](https://github.com/nmoinvaz/minizip/tree/dev)|Active [![Dev Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=dev)](https://travis-ci.org/nmoinvaz/minizip/branches)|2.x|Latest development code|
|[1.2](https://github.com/nmoinvaz/minizip/tree/1.2)|Stale| 1.x|Drop-in replacement for zlib's minizip that includes WinZip AES encryption, disk splitting, I/O buffering and some additional fixes.|
|[1.1](https://github.com/nmoinvaz/minizip/tree/1.1)|Stale| 1.x|Original minizip as of zlib 1.2.11.|

## History

Minizip was originally developed by [Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html) and 
had been contributed to by many people. As part of the zlib distribution, Mark Adler still maintains the
original [minizip](https://github.com/madler/zlib/tree/master/contrib/minizip) project which is included in this repository as a reference.

My work with the minizip library began in 2006 when I started submitting bugs I found to 
Gilles Vollant. In 2010, I implemented some additional features like WinZip AES encryption, disk splitting, and 
I/O buffering that were necessary for another project I was working on. Shortly after, I created this public repository 
so I could share these and other improvements with the rest of the world. I have been maintaining and actively 
developing this code base ever since. At the beginning of 2017, I began the work to refactor and rewrite 
the library as version 2 because it had become difficult to maintain and code readability suffered over the years.

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
+ Legacy character encoding support CP437, CP932, CP936, CP950.
+ Turn off compilation of compression, decompression, or encryption.
+ Windows (Win32 & WinRT), macOS and Linux platform support.
+ Streaming interface for easy implementation of additional platforms.
+ Support for Apple's compression library ZLIB implementation.
+ Zero out local file header information.
+ Zip/unzip of central directory to reduce size.
+ Ability to generate and verify CMS signature for each entry.
+ Recover the central directory if it is corrupt or missing.
+ Example minizip command line tool.

## Build

To generate project files for your platform:

1. [Download and install](https://cmake.org/install/) cmake.
2. Run cmake in the minizip directory.

```
cmake . -DMZ_BUILD_TEST=ON
cmake --build .
```

## Build Options

| Name | Description | Default Value |
|:- |:-|:-:|
| MZ_COMPAT | Enables compatibility layer | ON |
| MZ_ZLIB | Enables ZLIB compression | ON |
| MZ_BZIP2 | Enables BZIP2 compression | ON |
| MZ_LZMA | Enables LZMA compression | ON |
| MZ_PKCRYPT | Enables PKWARE traditional encryption | ON |
| MZ_WZAES | Enables WinZIP AES encryption | ON |
| MZ_LIBCOMP | Enables Apple compression | OFF |
| MZ_OPENSSL | Enables OpenSSL encryption | OFF |
| MZ_BRG | Enables Brian Gladman's library | OFF |
| MZ_COMPRESS_ONLY | Only support compression | OFF |
| MZ_DECOMPRESS_ONLY | Only support decompression | OFF |
| MZ_BUILD_TEST | Builds minizip test executable | OFF |
| MZ_BUILD_UNIT_TEST | Builds minizip unit test project | OFF |
| MZ_BUILD_FUZZ_TEST | Builds minizip fuzz executables | OFF |

## Contents

| File(s) | Description |
|:- |:-|
| minizip.c | Sample application |
| mz_compat.\* | Minizip 1.x compatibility layer |
| mz.h | Error codes and flags |
| mz_os\* | Platform specific file/utility functions |
| mz_crypt\* | Configuration specific crypto/hashing functions |
| mz_strm.\* | Stream interface |
| mz_strm_buf.\* | Buffered stream |
| mz_strm_bzip.\* | BZIP2 stream using libbzip2 |
| mz_strm_libcomp.\* | Apple compression stream |
| mz_strm_lzma.\* | LZMA stream using liblzma |
| mz_strm_mem.\* | Memory stream |
| mz_strm_split.\* | Disk splitting stream |
| mz_strm_pkcrypt.\* | PKWARE traditional encryption stream |
| mz_strm_os\* | Platform specific file stream |
| mz_strm_wzaes.\* | WinZIP AES stream |
| mz_strm_zlib.\* | Deflate stream using zlib |
| mz_zip.\* | Zip format |
| mz_zip_rw.\* | Zip reader/writer |

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
