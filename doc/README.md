# minizip-ng Documentation  <!-- omit in toc -->

### Table of Contents

- [API](#api)
- [Limitations](#limitations)
- [Minimum OS Requirements](#minimum-os-requirements)
- [Xcode Instructions](#xcode-instructions)
- [Zlib Configuration](#zlib-configuration)
- [Upgrading from 1.x](#upgrading-from-1x)
- [Security Considerations](#security-considerations)
- [Using Streams](#using-streams)
  - [Memory Stream](#memory-stream)
  - [Buffered Stream](#buffered-stream)
  - [Disk Splitting Stream](#disk-splitting-stream)
  - [Additional Code Examples](#additional-code-examples)

## API

### Constants <!-- omit in toc -->

|Prefix|Description|
|-|-|
|[MZ_COMPRESS_LEVEL](mz_compress_level.md)|Compression level enumeration|
|[MZ_COMPRESS_METHOD](mz_compress_method.md)|Compression method enumeration|
|[MZ_ENCODING](mz_encoding.md)|Character encoding enumeration|
|[MZ_ERROR](mz_error.md)|Error constants|
|[MZ_HASH](mz_hash.md)|Hash algorithms and digest sizes
|[MZ_HOST_SYSTEM](mz_host_system.md)|System identifiers|
|[MZ_OPEN_MODE](mz_open_mode.md)|Stream open modes|
|[MZ_SEEK](mz_seek.md)|Stream seek origins|
|[MZ_ZIP64](mz_zip64.md)|Zip64 extrafield options|

### Interfaces <!-- omit in toc -->

|Name|Description|
|-|-|
|MZ_COMPAT|Old minizip 1.x compatibility layer|
|[MZ_OS](mz_os.md)|Operating system level file system operations|
|[MZ_ZIP](mz_zip.md)|Zip archive and entry interface |
|[MZ_ZIP_RW](mz_zip_rw.md)|Easy zip file extraction and creation|

### Structures <!-- omit in toc -->

|Name|Description|
|-|-|
|[MZ_ZIP_FILE](mz_zip_file.md)|Zip entry information|

### Extrafield Proposals <!-- omit in toc -->

The zip reader and writer interface provides support for extended hash algorithms for zip entries and compression of the central directory. In order to add support for these features, extrafields were added and are described in the [minizip extrafield documentation](mz_extrafield.md).

## Limitations

+ Archives are required to have a central directory unless recovery mode is enabled.
+ Central directory header values should be correct and it is necessary for the compressed size to be accurate for encryption.
+ Central directory is the only data stored on the last disk of a split-disk archive and doesn't follow disk size restrictions.

### Third-Party Limitations <!-- omit in toc -->

* Windows Explorer zip extraction utility does not support disk splitting. [1](https://stackoverflow.com/questions/31286707/the-same-volume-can-not-be-used-as-both-the-source-and-destination)
* macOS archive utility does not properly support ZIP files over 4GB. [1](http://web.archive.org/web/20140331005235/http://www.springyarchiver.com/blog/topic/topic/203) [2](https://bitinn.net/10716/)

## Minimum OS Requirements

Actively supported minimum operating system versions:

* Windows Vista
* macOS 10.13
* Ubuntu 18

Pull requests can be submitted to maintain support for older versions.

## Xcode Instructions

To create an Xcode project with CMake use:
```
cmake -G Xcode .
```

## Zlib Configuration

By default, if zlib is not found, it will be pulled as an external project and installed. This requires [Git](https://git-scm.com/) to be installed and available to your command interpreter.

* To specify your own zlib repository use `ZLIB_REPOSITORY` and/or `ZLIB_TAG`.
* To specify your own zlib installation use `ZLIB_LIBRARY` and `ZLIB_INCLUDE_DIR`.

**Compiling with Zlib-ng**

To compile using zlib-ng use the following cmake args:

```
-DZLIB_REPOSITORY=https://github.com/zlib-ng/zlib-ng -DZLIB_TAG=develop
```
**Compiling and Installing Zlib (Windows)**

To compile and install zlib to the Program Files directory with an Administrator command prompt:

```
cmake -DCMAKE_INSTALL_PREFIX="C:\Program Files (x86)\zlib" .
cmake --build . --config Release --target INSTALL
```
**Configure Existing Zlib Installation (Windows)**

To configure cmake with an existing zlib installation point cmake to your install directories:

```
cmake -DZLIB_LIBRARY:FILEPATH="C:\Program Files (x86)\zlib\lib\zlibstaticd.lib" .
cmake -DZLIB_INCLUDE_DIR:PATH="C:\Program Files (x86)\zlib\include" .
```

## Upgrading from 1.x

If you are using CMAKE it will automatically include all the files and define all the #defines
required based on your configuration and it will also build the project files necessary for your platform.

However, for some projects it may be necessary to drop in the new files into an existing project. In that
instance, some #defines will have to be set as they have changed.

|1.x|2.x|Description|
|-|-|:-|
||HAVE_ZLIB|Compile with ZLIB library. Older versions of Minizip required ZLIB. It is now possible to alternatively compile only using liblzma library.|
||HAVE_LZMA|Compile with LZMA support.|
|HAVE_BZIP2|HAVE_BZIP2|Compile with BZIP2 library support.|
|HAVE_APPLE_COMPRESSION|HAVE_LIBCOMP|Compile using Apple Compression library.|
|HAVE_AES|HAVE_WZAES|Compile using AES encryption support.|
||HAVE_PKCRYPT|Compile using PKWARE traditional encryption support. Previously this was automatically assumed.|
|NOUNCRYPT|Nearest to MZ_ZIP_NO_ENCRYPTION|Previously turn off all decryption support.|
|NOCRYPT|Nearest to MZ_ZIP_NO_ENCRYPTION|Previously turned off all encryption support.|
||MZ_ZIP_NO_ENCRYPTION|Turns off all encryption/decryption support.|
|NO_ADDFILEINEXISTINGZIP||Not currently supported.|
||MZ_ZIP_NO_COMPRESSION|Intended to reduce compilation size if not using zipping functionality.|
||MZ_ZIP_NO_COMPRESSION|Intended to reduce compilation size if not using zipping functionality.|

At a minimum HAVE_ZLIB and HAVE_PKCRYPT will be necessary to be defined for drop-in replacement. To determine which files to drop in, see the Contents section of the [README](https://github.com/zlib-ng/minizip-ng/blob/master/README.md).

## Security Considerations

### WinZip AES <!-- omit in toc -->

When compressing an archive with WinZIP AES enabled, by default it uses 256 bit encryption. During decompression whatever bit encryption was specified when the entry was added to the archive will be used.

WinZip AES encryption uses CTR on top of ECB which prevents identical ciphertext blocks that might occur when using ECB by itself. More details about the WinZIP AES format can be found in the [winzip documentation](zip/winzip_aes.md).

### How to Create a Secure Zip <!-- omit in toc -->

In order to create a secure zip file you must:

* Use WinZIP AES encryption
* Zip the central directory
* Sign the zip file using a certificate

The combination of using AES encryption and zipping the central directory prevents data leakage through filename exposure.

## Using Streams

All input/output operations are done through the use of streams.

### Memory Stream

To unzip from a zip file in memory pass the memory stream to the open function.
```c
uint8_t *zip_buffer = NULL;
int32_t zip_buffer_size = 0;
void *mem_stream = NULL;
void *zip_handle = NULL;

/* TODO: fill zip_buffer with zip contents.. */

mem_stream = mz_stream_mem_create();
mz_stream_mem_set_buffer(mem_stream, zip_buffer, zip_buffer_size);
mz_stream_open(mem_stream, NULL, MZ_OPEN_MODE_READ);

zip_handle = mz_zip_create();
err = mz_zip_open(zip_handle, mem_stream, MZ_OPEN_MODE_READ);

/* TODO: unzip operations.. */

mz_zip_close(zip_handle);
mz_zip_delete(&zip_handle);

mz_stream_mem_delete(&mem_stream);
```

To create a zip file in memory first create a growable memory stream and pass it to the open function.

```c
void *mem_stream = NULL;
void *zip_handle = NULL;

mem_stream = mz_stream_mem_create();
mz_stream_mem_set_grow_size(mem_stream, (128 * 1024));
mz_stream_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE);

zip_handle = mz_zip_create();
err = mz_zip_open(zip_handle, mem_stream, MZ_OPEN_MODE_WRITE);

/* TODO: unzip operations.. */

mz_zip_close(zip_handle);
mz_zip_delete(&zip_handle);

mz_stream_mem_delete(&mem_stream);
```

For a complete example, see test_stream_mem() in [test.c](https://github.com/nmoinvaz/minizip/blob/master/test/test.c).

### Buffered Stream

By default the library will read bytes typically one at a time. The buffered stream allows for buffered read and write operations to improve I/O performance.

```c
void *stream = NULL;
void *buf_stream = NULL;
void *zip_handle = NULL;

stream = mz_stream_os_create()

/* TODO: open os stream.. */

buf_stream = mz_stream_buffered_create();
mz_stream_buffered_open(buf_stream, NULL, MZ_OPEN_MODE_READ);
mz_stream_buffered_set_base(buf_stream, stream);

zip_handle = mz_zip_create();
err = mz_zip_open(zip_handle, buf_stream, MZ_OPEN_MODE_READ);

/* TODO: unzip operation.. */

mz_zip_close(zip_handle);
mz_zip_delete(&zip_handle);

mz_stream_buffered_delete(&buf_stream);
```

### Disk Splitting Stream

To create an archive with multiple disks use the disk splitting stream and supply a disk size value in bytes.

```c
void *stream = NULL;
void *split_stream = NULL;
void *zip_handle = NULL;

stream = mz_stream_os_create();

split_stream = mz_stream_split_create();
mz_stream_split_set_prop_int64(split_stream, MZ_STREAM_PROP_DISK_SIZE, 64 * 1024);
mz_stream_set_base(split_stream, stream);
mz_stream_open(split_stream, path..

zip_handle = mz_zip_create();
err = mz_zip_open(zip_handle, split_stream, MZ_OPEN_MODE_WRITE);

/* TODO: unzip operation.. */

mz_zip_close(zip_handle);
mz_zip_delete(&zip_handle);

mz_stream_buffered_delete(&split_stream);
```

### Additional Code Examples

Some of these may be out of date, but they can also be helpful.

* [Compressed stream tests](https://github.com/zlib-ng/minizip-ng/blob/master/test/test_stream_compress.cc)
* [Code to copy raw entries from one zip file to another](https://gist.github.com/chenxiaolong/bcbb0835182ef16a25f09db8d99e0619) by chenxiaolong
* [Buffered streaming](https://gist.github.com/chenxiaolong/dbab3fbef51b9d0fa969e220dbb85967) by chenxiaolong