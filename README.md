# MiniZip 1.3.0

This library is a refactoring of the minizip contribution found in the zlib distribution. It is based on the original work of [Gilles Vollant](http://www.winimage.com/zLibDll/minizip.html) that has been contributed to by many people over the years.

## Features

### Streams

This library has been refactored with streaming.

#### Memory Streaming

To unzip from a zip file in memory create a memory stream and pass it to the unzip open functions.
```
uint8_t *zip_buffer = NULL;
int32_t zip_buffer_size = 0;
void *mem_stream = NULL;

// fill zip_buffer with zip contents
mz_stream_mem_create(&mem_stream);
mz_stream_mem_set_buffer(mem_stream, zip_buffer, zip_buffer_size);
mz_stream_open(mem_stream, NULL, MZ_STREAM_MODE_READ);

void *unz_handle = mz_unzip_open(mem_stream);
// do unzip operations

mz_stream_mem_delete(&mem_stream);
```

To create a zip file in memory first create a growable memory stream and pass it to the zip open functions.

```
void *mem_stream = NULL;

mz_stream_mem_create(&mem_stream);
mz_stream_mem_set_grow(mem_stream, 1);
mz_stream_mem_set_grow_size(mem_stream, (128 * 1024));
mz_stream_open(mem_stream, NULL, MZ_STREAM_MODE_CREATE);

void *zip_handle = mz_zip_open(0, 0, mem_stream);
// do unzip operations

mz_stream_mem_delete(&mem_stream);
```
#### Buffered Streaming

By default the library will read bytes typically one at a time. The buffered stream allows for buffered read and write operations to improve I/O performance.

```
void *stream = NULL;
void *buf_stream = NULL;

mz_stream_os_create(&stream)
// do open os stream

mz_stream_buffered_create(&buf_stream);
mz_stream_buffered_open(buf_stream, NULL, MZ_STREAM_MODE_READ)
mz_stream_buffered_set_base(buf_stream, stream);

void *unz_handle = mz_unzip_open(buf_stream);
```
### Compression Methods

#### BZIP2

+ Requires #define HAVE_BZIP2
+ Requires [BZIP2](http://www.bzip.org/) library

#### LZMA

+ Requires #define HAVE_LZMA
+ Requires [liblzma](https://tukaani.org/xz/) library

### Encryption

#### [WinZIP AES Encryption](http://www.winzip.com/aes_info.htm)

+ Requires #define HAVE_AES
+ Requires [Brian Gladman's](https://github.com/BrianGladman/aes) AES library

When zipping with a password it will always use AES 256-bit encryption.
When unzipping it will use AES decryption only if necessary. Does not support central directory or local file header encryption since nobody outside of PKWARE supports it.

### Platforms

This library is supported on Windows, Macintosh, and Linux.

+ Windows: Visual Studio 2015
+ Macintosh: XCode
+ Linux: Qt Creator / Qbs

#### Windows RT

+ Requires #define IOWIN32_USING_WINRT_API
