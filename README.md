Minizip zlib contribution that includes:

- AES encryption
- I/O buffering
- PKWARE disk spanning
- Visual Studio project files

It also has the latest bug fixes that having been found all over the internet including the minizip forum and zlib developer's mailing list.

*AES Encryption*

+ Requires all files in the aes folder
+ Requires #define HAVE_AES

When using the zip library with password protection it will use AES 256-bit encryption. 
When using the unzip library it will automatically use AES when applicable. 

*I/O Buffering*

```
ourbuffer_t buffered = {0};
zlib_filefunc64_def fileFunc64 = {0};
    
fill_win32_filefunc64W(&buffered->filefunc64);
fill_buffer_filefunc64(&fileFunc64, buffered);
    
unzOpen2_64(wFilename, &fileFunc64)
```

*PKWARE disk spanning*

To create an archive with multiple disks use zipOpen3_64 supplying a disk_size value in bytes.

```
extern zipFile ZEXPORT zipOpen3_64 OF((const void *pathname, int append, 
  ZPOS64_T disk_size, zipcharpc* globalcomment, zlib_filefunc64_def* pzlib_filefunc_def));
```
The central directory is the only data stored in the .zip and doesn't follow disk_size restrictions.

When using the unzip library it will automatically determine when in needs to span disks.