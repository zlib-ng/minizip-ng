# minizip 2.5.3

minizip is a zip manipulation library written in C that is supported on Windows, macOS, and Linux. 

[![License: Zlib](https://img.shields.io/badge/license-zlib-lightgrey.svg)](https://github.com/nmoinvaz/minizip/blob/master/LICENSE)

Maintained by Nathan Moinvaziri.

## Fork Motivation and History

This library is a complete refactoring of the minizip contribution found in the zlib
distribution. The motivation for this fork has been the inclusion of advanced features, 
improvements in code maintainability and readability, and the reduction of duplicate code.

Minizip was originally developed by [Gilles Vollant](http://www.winimage.com/zLibDll/minizip.html) and 
had been contributed to by many people. As part of the zlib distribution, Mark Adler has maintained the
original [minizip](https://github.com/madler/zlib/tree/master/contrib/minizip) project.

In 2006, I began working with the minizip project and started submitting bugs I found in the library to 
Gilles Vollant via e-mail. In 2010, I implemented some additional features like disk splitting and I/O buffering.
My continued work on the project necessitated setting up a public repository so I could share my improvements
with the rest of the world. I have been maintaining this fork of the project ever since. In 2017, I began the 
task of refactoring and rewriting most of library as it had become difficult to maintain and code readability 
had suffered over the years.

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
+ Compatibility interface for older versions of minizip.
+ Example minizip command line tool.

## Build

To generate project files for your platform:

1. [Download and install](https://cmake.org/install/) cmake.
2. [Download](https://zlib.net/) and install zlib if it is not installed on your system.
3. Run cmake in the minizip directory.

```
cmake . -DBUILD_TEST=ON
cmake --build .
```

## Build Options

| Name | Description | Default Value |
|:- |:-|:-:|
| USE_ZLIB | Enables ZLIB compression | ON |
| USE_BZIP2 | Enables BZIP2 compression | ON |
| USE_LZMA | Enables LZMA compression | ON |
| USE_PKCRYPT | Enables PKWARE traditional encryption | ON |
| USE_AES | Enables WinZIP AES encryption | ON |
| COMPRESS_ONLY | Only support compression | OFF |
| DECOMPRESS_ONLY | Only support decompression | OFF |
| BUILD_TEST | Builds minizip test executable | OFF |

## Zlib Installation (Windows)

Option 1. Install the zlib package to the Program Files directory with an Administrator command prompt.

```
cmake . -DCMAKE_INSTALL_PREFIX=%PROGRAMFILES%\zlib
cmake --build . --config Release --target INSTALL
```

Option 2. Compile zlib in minizip's lib directory. 

```
cmake .
cmake --build . --config Release
```

Navigate back to the minizip directory and before building run:

```
cmake . -DZLIB_LIBRARY=lib\zlib\release\zlibstatic.lib -DZLIB_INCLUDE_DIR=lib\zlib\
```

## Contents

| File(s) | Description | Required |
|:- |:-|:-:|
| minizip.c | Sample application | No |
| mz_compat.\* | Minizip 1.0 compatibility layer | No |
| mz.h | Error codes and flags | Yes |
| mz_os\* | OS specific helper functions | Encryption, Disk Splitting |
| mz_strm.\* | Stream interface | Yes |
| mz_strm_aes.\* | WinZIP AES stream | No |
| mz_strm_buf.\* | Buffered stream | No |
| mz_strm_bzip.\* | BZIP2 stream using libbzip2 | No |
| mz_strm_crc32.\* | CRC32 stream | Yes |
| mz_strm_lzma.\* | LZMA stream using liblzma | zlib or liblzma |
| mz_strm_mem.\* | Memory stream | Yes |
| mz_strm_split.\* | Disk splitting stream | No |
| mz_strm_pkcrypt.\* | PKWARE traditional encryption stream | No |
| mz_strm_posix.\* | File stream using Posix functions | Non-windows systems |
| mz_strm_win32.\* | File stream using Win32 API functions | Windows systems |
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

## Limitations

+ Archives are required to have a central directory.
+ Central directory header values should be correct and it is necessary for the compressed size to be accurate for AES encryption.
+ Central directory encryption is not supported due to licensing restrictions mentioned by PKWARE in their zip appnote.
+ Central directory is the only data stored on the last disk of a split-disk archive and doesn't follow disk size restrictions.

## Acknowledgments

Thanks to [Gilles Vollant](http://www.winimage.com/zLibDll/minizip.html) on which this work is originally based on. 

Thanks go out to all the people who have taken the time to contribute code reviews, testing and/or patches. This project would not have been nearly as good without you.

The [ZIP format](https://github.com/nmoinvaz/minizip/blob/master/doc/appnote.txt) was defined by Phil Katz of PKWARE.
