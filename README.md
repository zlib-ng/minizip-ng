Minizip zlib contribution that includes:

- AES encryption
- I/O buffering
- PKWARE disk spanning
- Visual Studio 2008 project files

It also has the latest bug fixes that having been found all over the internet including the minizip forum and zlib developer's mailing list.

*AES Encryption*

+ Requires all files in the aes folder
+ Requires #define HAVE_AES

When using the zip library with password protection it will use AES 256-bit encryption. 
When using the unzip library it will automatically use AES when applicable. 

*I/O Buffering*

Improves I/O performance by buffering read and write operations.
```
zlib_filefunc64_def filefunc64 = {0};
ourbuffer_t buffered = {0};
    
fill_win32_filefunc64(&buffered->filefunc64);
fill_buffer_filefunc64(&filefunc64, buffered);
    
unzOpen2_64(filename, &filefunc64)
```

*I/O Memory*

To unzip from a zip file in memory use fill_memory_filefunc and supply a proper ourmemory_t structure.
```
zlib_filefunc_def filefunc32 = {0};
ourmemory_t zipmem = {0};

zipmem.size = bufsize;
zipmem.base = (char *)malloc(zipmem.size);
memcpy(zipmem.base, buffer, zipmem.size);
    
fill_memory_filefunc(&filefunc32, &zipmem);

unzOpen2(filename, &filefunc32);
```

*PKWARE disk spanning*

To create an archive with multiple disks use zipOpen3_64 supplying a disk_size value in bytes.

```
extern zipFile ZEXPORT zipOpen3_64 OF((const void *pathname, int append, 
  ZPOS64_T disk_size, zipcharpc* globalcomment, zlib_filefunc64_def* pzlib_filefunc_def));
```
The central directory is the only data stored in the .zip and doesn't follow disk_size restrictions.

When using the unzip library it will automatically determine when in needs to span disks.
