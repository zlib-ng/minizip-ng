# Minizip 2.5.2

This library is a refactoring of the minizip contribution found in the zlib
distribution and is supported on Windows, macOS, and Linux. The motivation
for this work has been the inclusion of advanced features, improvements in
code maintainability and readability, and the reduction of duplicate code.
It is based on the original work of
[Gilles Vollant](http://www.winimage.com/zLibDll/minizip.html) that has been
contributed to by many people over the years.

Dev: [![Dev Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=dev)](https://travis-ci.org/nmoinvaz/minizip/branches)
Master: [![Master Branch Status](https://api.travis-ci.org/nmoinvaz/minizip.svg?branch=master)](https://travis-ci.org/nmoinvaz/minizip/branches)

For my older fork of this library checkout the [1.2](https://github.com/nmoinvaz/minizip/tree/1.2) branch.
For the original work maintained by Mark Adler checkout the zlib minizip  [contrib](https://github.com/madler/zlib/tree/master/contrib/minizip).

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
+ Unicode filename support through UTF-8 encoding.
+ IBM Codepage 437 legacy character encoding support.
+ Turn off compilation of compression, decompression, or encryption.
+ Windows (Win32 & WinRT), macOS and Linux platform support.
+ Streaming interface for easy implementation of additional platforms.
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
