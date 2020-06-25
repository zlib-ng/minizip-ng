# minizip 2.10.0

minizip is a zip manipulation library written in C that is supported on Windows, macOS, and Linux.

[![Master Branch Status](https://github.com/nmoinvaz/minizip/workflows/CI/badge.svg)](https://github.com/nmoinvaz/minizip/actions)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/minizip.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:minizip)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/53d48ca8fec549f4a8b39cf95cba6ad6)](https://www.codacy.com/manual/nmoinvaz/minizip?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=nmoinvaz/minizip&amp;utm_campaign=Badge_Grade)
[![CodeFactor](https://www.codefactor.io/repository/github/nmoinvaz/minizip/badge)](https://www.codefactor.io/repository/github/nmoinvaz/minizip)
[![License: Zlib](https://img.shields.io/badge/license-zlib-lightgrey.svg)](https://github.com/nmoinvaz/minizip/blob/master/LICENSE)
[![codecov.io](https://codecov.io/github/nmoinvaz/minizip/coverage.svg?branch=dev)](https://codecov.io/github/nmoinvaz/minizip/)

Developed and maintained by Nathan Moinvaziri.

## Branches

|Name|Description|
|:-|:-|
|[master](https://github.com/nmoinvaz/minizip/tree/master)|Modern rewrite that includes more advanced features, improvements in code maintainability and readability, and the reduction of duplicate code. Compatibility layer provided for older versions.|
|[dev](https://github.com/nmoinvaz/minizip/tree/dev)|Latest development code|
|[1.2](https://github.com/nmoinvaz/minizip/tree/1.2)|Drop-in replacement for zlib's minizip that includes WinZip AES encryption, disk splitting, I/O buffering and some additional fixes.|
|[1.1](https://github.com/nmoinvaz/minizip/tree/1.1)|Original minizip as of zlib 1.2.11.|

## History

Minizip was originally developed by [Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html) in 1998. It was first included in the zlib distribution as an additional code contribution starting in zlib 1.1.2. Since that time, it has been continually improved upon and contributed to by many people. The original [project](https://github.com/madler/zlib/tree/master/contrib/minizip) can still be found in the zlib distribution that is maintained by Mark Adler.

My work with the minizip library started in 2006 when I fixed a few bugs I found and submitted them to
Gilles Vollant. In 2010, I implemented WinZip AES encryption, disk splitting, and
I/O buffering that were necessary for another project I was working on. Shortly after, I created this public repository
so I could share my improvements with the community. In early 2017, I began the work to refactor and rewrite
the library as version 2 because it had become difficult to maintain and code readability suffered over the years.

## Features

+ Creating and extracting zip archives.
+ Adding and removing entries from zip archives.
+ Read and write raw zip entry data.
+ Reading and writing zip archives from memory.
+ Zlib, BZIP2, LZMA, and ZSTD compression methods.
+ Password protection through Traditional PKWARE and [WinZIP AES](https://www.winzip.com/aes_info.htm) encryption.
+ Buffered streaming for improved I/O performance.
+ NTFS timestamp support for UTC last modified, last accessed, and creation dates.
+ Disk split support for splitting zip archives into multiple files.
+ Preservation of file attributes across file systems.
+ Follow and store symbolic links.
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

1. [Download and install](https://cmake.org/install/) cmake (version 3.11 or later recommended).
2. Run cmake in the minizip directory.

```
cmake . -DMZ_BUILD_TEST=ON
cmake --build .
```

## Build Options

| Name               | Description                           | Default Value |
|:-------------------|:--------------------------------------|:-------------:|
| MZ_COMPAT          | Enables compatibility layer           |      ON       |
| MZ_ZLIB            | Enables ZLIB compression              |      ON       |
| MZ_BZIP2           | Enables BZIP2 compression             |      ON       |
| MZ_LZMA            | Enables LZMA compression              |      ON       |
| MZ_ZSTD            | Enables ZSTD compression              |      ON       |
| MZ_PKCRYPT         | Enables PKWARE traditional encryption |      ON       |
| MZ_WZAES           | Enables WinZIP AES encryption         |      ON       |
| MZ_LIBCOMP         | Enables Apple compression             |      OFF      |
| MZ_OPENSSL         | Enables OpenSSL encryption            |      OFF      |
| MZ_LIBBSD          | Builds with libbsd crypto random      |      ON       |
| MZ_BRG             | Enables Brian Gladman's library       |      OFF      |
| MZ_SIGNING         | Enables zip signing support           |      ON       |
| MZ_COMPRESS_ONLY   | Only support compression              |      OFF      |
| MZ_DECOMPRESS_ONLY | Only support decompression            |      OFF      |
| MZ_BUILD_TEST      | Builds minizip test executable        |      OFF      |
| MZ_BUILD_UNIT_TEST | Builds minizip unit test project      |      OFF      |
| MZ_BUILD_FUZZ_TEST | Builds minizip fuzz executables       |      OFF      |
| MZ_CODE_COVERAGE   | Build with code coverage flags        |      OFF      |
| MZ_PROJECT_SUFFIX  | Project name suffix for packaging     |               |
| MZ_FILE32_API      | Builds using posix 32-bit file api    |      OFF      |

## Third-Party Libraries

|Project|License|CMake Option|Comments|
|-|-|-|-|
|[aes](https://github.com/BrianGladman/aes)|[license](https://github.com/BrianGladman/aes/blob/master/license.txt)|`MZ_BRG`|Written by Brian Gladman. Compiled in when system crypto functions are unavailable.|
[bzip2](https://www.sourceware.org/bzip2/)|[license](https://github.com/nmoinvaz/minizip/blob/dev/lib/bzip2/LICENSE)|`MZ_BZIP2`|Written by Julian Seward.|
|[liblzma](https://tukaani.org/xz/)|Public domain|`MZ_LZMA`|Written by Igor Pavlov and Lasse Collin. Modifications were made to support the ZIP file format specification.|
|[sha](https://github.com/BrianGladman/sha)|[license](https://github.com/BrianGladman/aes/blob/master/license.txt)|`MZ_BRG`|Written by Brian Gladman. Compiled in when system crypto functions are unavailable.|
|[zlib](https://zlib.net/)|zlib|`MZ_ZLIB`|Written by Mark Adler and Jean-loup Gailly. Not included in this repository. Or alternatively, [zlib-ng](https://github.com/Dead2/zlib-ng) by Hans Kristian Rosbach.|
|[zstd](https://github.com/facebook/zstd)|[BSD](https://github.com/facebook/zstd/blob/dev/LICENSE)|`MZ_ZSTD`|Written by Facebook. Not included in this repository.|

This project uses the zlib [license](LICENSE).

## Acknowledgments

Thanks go out to all the people who have taken the time to contribute code reviews, testing and/or patches. This project would not have been as good without you.

Thanks to [Gilles Vollant](https://www.winimage.com/zLibDll/minizip.html) on which this work is originally based on.

The [ZIP format](https://github.com/nmoinvaz/minizip/blob/master/doc/appnote.txt) was defined by Phil Katz of PKWARE.
