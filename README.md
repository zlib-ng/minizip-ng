# Minizip zlib contribution fork

Contains the latest bug fixes that having been found all over the internet including the [old minizip forum](https://web.archive.org/web/20121015065401/http://www.winimage.info/forum/) and zlib developer's mailing list along with some additional features. Based on the original work of [Gilles Vollant](http://www.winimage.com/zLibDll/minizip.html) and contributed to by many people over the years.

## Features

### Streams

The library has been refactored around streams.

#### Memory Streaming

To unzip from a zip file in memory create a memory stream and pass it to the unzip open functions.
```
uint8_t *zip_buffer = ...
int32_t zip_buffer_size = 0;
void *mem_stream = NULL;

// create memory buffer stream and set our buffer
mz_stream_mem_create(&mem_stream);
mz_stream_mem_set_buffer(mem_stream, zip_buffer, zip_buffer_size);
mz_stream_open(mem_stream, NULL, MZ_STREAM_MODE_READ);

void *unz_handle = mz_unzip_open(NULL, mem_stream);
// do unzip operations here

mz_stream_mem_delete(&mem_stream);
```

To create a zip file in memory first create a growable memory stream and pass it to the zip open functions.

```
void *mem_stream = NULL;

// create memory buffer stream and set our buffer
mz_stream_mem_create(&mem_stream);
mz_stream_mem_set_grow(mem_stream, 1);
mz_stream_mem_set_grow_size(mem_stream, 128 * 1024);
mz_stream_open(mem_stream, NULL, MZ_STREAM_MODE_CREATE);

void *zip_handle = mz_zip_open(NULL, 0, 0, mem_stream);
// do zip operations here

mz_stream_mem_delete(&mem_stream);
```
### Compression Methods

#### BZIP2

+ Requires #define HAVE_BZIP2
+ Requires BZIP2 library

#### LZMA

+ Requires #define HAVE_LZMA
+ Requires BZIP2 library

### Encryption

#### [WinZIP AES Encryption](http://www.winzip.com/aes_info.htm)

+ Requires #define HAVE_AES
+ Requires AES library

When zipping with a password it will always use AES 256-bit encryption.
When unzipping it will use AES decryption only if necessary. Does not support central directory or local file header encryption.

#### Whole Archive Encryption



### Platforms

#### Windows RT

+ Requires #define IOWIN32_USING_WINRT_API

### PKWARE disk spanning

To create an archive with multiple disks use zipOpen3_64 supplying a disk_size value in bytes.

```
extern zipFile ZEXPORT zipOpen3_64(const void *pathname, int append,
  ZPOS64_T disk_size, zipcharpc* globalcomment, zlib_filefunc64_def* pzlib_filefunc_def);
```
The central directory is the only data stored in the .zip and doesn't follow disk_size restrictions.

When unzipping it will automatically determine when in needs to span disks.

### I/O Buffering

Improves I/O performance by buffering read and write operations.
```
zlib_filefunc64_def filefunc64 = {0};
ourbuffer_t buffered = {0};

fill_win32_filefunc64(&buffered->filefunc64);
fill_buffer_filefunc64(&filefunc64, buffered);

unzOpen2_64(filename, &filefunc64)
```

### Apple libcompression

+ Requires #define HAVE_APPLE_COMPRESSION
