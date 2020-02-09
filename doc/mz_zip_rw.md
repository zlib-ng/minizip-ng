## MZ_ZIP_RW <!-- omit in toc -->

The _mz_zip_reader_ and _mz_zip_writer_ objects allows you to easily extract or create zip files.

- [Reader Callbacks](#reader-callbacks)
  - [mz_zip_reader_overwrite_cb](#mzzipreaderoverwritecb)
  - [mz_zip_reader_password_cb](#mzzipreaderpasswordcb)
  - [mz_zip_reader_progress_cb](#mzzipreaderprogresscb)
  - [mz_zip_reader_entry_cb](#mzzipreaderentrycb)
- [Reader Open/Close](#reader-openclose)
  - [mz_zip_reader_is_open](#mzzipreaderisopen)
  - [mz_zip_reader_open](#mzzipreaderopen)
  - [mz_zip_reader_open_file](#mzzipreaderopenfile)
  - [mz_zip_reader_open_file_in_memory](#mzzipreaderopenfileinmemory)
  - [mz_zip_reader_open_buffer](#mzzipreaderopenbuffer)
  - [mz_zip_reader_close](#mzzipreaderclose)
- [Reader Entry Enumeration](#reader-entry-enumeration)
  - [mz_zip_reader_goto_first_entry](#mzzipreadergotofirstentry)
  - [mz_zip_reader_goto_next_entry](#mzzipreadergotonextentry)
  - [mz_zip_reader_locate_entry](#mzzipreaderlocateentry)
- [Reader Entry](#reader-entry)
  - [mz_zip_reader_entry_open](#mzzipreaderentryopen)
  - [mz_zip_reader_entry_close](#mzzipreaderentryclose)
  - [mz_zip_reader_entry_read](#mzzipreaderentryread)
  - [mz_zip_reader_entry_has_sign](#mzzipreaderentryhassign)
  - [mz_zip_reader_entry_sign_verify](#mzzipreaderentrysignverify)
  - [mz_zip_reader_entry_get_hash](#mzzipreaderentrygethash)
  - [mz_zip_reader_entry_get_first_hash](#mzzipreaderentrygetfirsthash)
  - [mz_zip_reader_entry_get_info](#mzzipreaderentrygetinfo)
  - [mz_zip_reader_entry_is_dir](#mzzipreaderentryisdir)
  - [mz_zip_reader_entry_save](#mzzipreaderentrysave)
  - [mz_zip_reader_entry_save_process](#mzzipreaderentrysaveprocess)
  - [mz_zip_reader_entry_save_file](#mzzipreaderentrysavefile)
  - [mz_zip_reader_entry_save_buffer](#mzzipreaderentrysavebuffer)
  - [mz_zip_reader_entry_save_buffer_length](#mzzipreaderentrysavebufferlength)
- [Reader Bulk Extract](#reader-bulk-extract)
  - [mz_zip_reader_save_all](#mzzipreadersaveall)
- [Reader Object](#reader-object)
  - [mz_zip_reader_set_pattern](#mzzipreadersetpattern)
  - [mz_zip_reader_set_password](#mzzipreadersetpassword)
  - [mz_zip_reader_set_raw](#mzzipreadersetraw)
  - [mz_zip_reader_get_raw](#mzzipreadergetraw)
  - [mz_zip_reader_get_zip_cd](#mzzipreadergetzipcd)
  - [mz_zip_reader_get_comment](#mzzipreadergetcomment)
  - [mz_zip_reader_set_encoding](#mzzipreadersetencoding)
  - [mz_zip_reader_set_sign_required](#mzzipreadersetsignrequired)
  - [mz_zip_reader_set_overwrite_cb](#mzzipreadersetoverwritecb)
  - [mz_zip_reader_set_password_cb](#mzzipreadersetpasswordcb)
  - [mz_zip_reader_set_progress_cb](#mzzipreadersetprogresscb)
  - [mz_zip_reader_set_progress_interval](#mzzipreadersetprogressinterval)
  - [mz_zip_reader_set_entry_cb](#mzzipreadersetentrycb)
  - [mz_zip_reader_get_zip_handle](#mzzipreadergetziphandle)
  - [mz_zip_reader_create](#mzzipreadercreate)
  - [mz_zip_reader_delete](#mzzipreaderdelete)

## Reader Callbacks

### mz_zip_reader_overwrite_cb

Callback that called before an existing file is about to be overwritten. It can be set by calling _mz_zip_reader_set_overwrite_cb_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|Pointer that is passed to _mz_zip_reader_set_overwrite_cb_|
|mz_zip_file *|file_info|Zip entry|
|const char *|path|Target path on disk|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK to overwrite, MZ_EXIST_ERROR to skip.|

**Example**

See _minizip_extract_overwrite_cb_ callback in minizip.c.

### mz_zip_reader_password_cb

Callback that is called before a password is required to extract a password protected zip entry. It can be set by calling _mz_zip_reader_set_password_cb_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|Pointer that is passed to _mz_zip_reader_set_password_cb_|
|mz_zip_file *|file_info|Zip entry|
|char *|password|Password character array buffer|
|int32|max_password|Maximum password size|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
static int32_t example_password_cb(void *handle, void *userdata, mz_zip_file *file_info, char *password, int32_t max_password) {
    strncpy(password, "my password", max_password);
    return MZ_OK;
}
mz_zip_reader_set_password_cb(zip_reader, 0, example_password_cb);
```

### mz_zip_reader_progress_cb

Callback that is called to report extraction progress. This can be set by calling _mz_zip_reader_set_progress_cb_.

Progress calculation depends on whether or not raw data is being extracted. If raw data, then use `position / file_info->compressed_size` otherwise use `position / file_info->uncompressed_size`.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|Pointer that is passed to _mz_zip_reader_progress_cb_|
|mz_zip_file *|file_info|Zip entry|
|int64_t|position|File position.|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See _minizip_extract_progress_cb_ in minizip.c.

### mz_zip_reader_entry_cb

Callback that is called when a new zip entry is starting extraction. It can be set by calling _mz_zip_reader_entry_cb_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|Pointer that is passed to _mz_zip_reader_entry_cb_|
|const char *|path|Target path on disk|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See _minizip_extract_entry_cb_ in minizip.c.

## Reader Open/Close

### mz_zip_reader_is_open

Checks to see if the zip file is open.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if open.|

**Example**
```
if (mz_zip_reader_is_open(zip_reader) == MZ_OK)
    printf("Zip file is open in reader\n");
```

### mz_zip_reader_open

 Opens zip file from stream.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|stream|_mz_stream_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if opened.|

**Example**
```
void *file_stream = NULL;
const char *path = "c:\\my.zip";

mz_zip_reader_create(&zip_reader);
mz_stream_os_create(&file_stream);

err = mz_stream_os_open(file_stream, path, MZ_OPEN_MODE_READ);
if (err == MZ_OK) {
    err = mz_zip_reader_open(zip_reader, file_stream);
    if (err == MZ_OK) {
        printf("Zip reader was opened %s\n", path);
        mz_zip_reader_close(zip_reader);
    }
}

mz_stream_os_delete(&file_stream);
mz_zip_reader_delete(&zip_reader);
```

### mz_zip_reader_open_file

Opens zip file from a file path.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|path|Path to zip file|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if opened.|

**Example**
```
const char *path = "c:\\my.zip";
mz_zip_reader_create(&zip_reader);
if (mz_zip_reader_open_file(zip_reader, path) == MZ_OK) {
    printf("Zip reader was opened %s\n", path);
    mz_zip_reader_close(zip_reader);
}
mz_zip_reader_delete(&zip_reader);
```

### mz_zip_reader_open_file_in_memory

Opens zip file from a file path into memory for faster access.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|path|Path to zip file|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if opened.|

**Example**
```
const char *path = "c:\\my.zip";
mz_zip_reader_create(&zip_reader);
if (mz_zip_reader_open_file_in_memory(zip_reader, path) == MZ_OK) {
    printf("Zip reader was opened in memory %s\n", path);
    mz_zip_reader_close(zip_reader);
}
mz_zip_reader_delete(&zip_reader);
```

### mz_zip_reader_open_buffer

Opens zip file from memory buffer.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint8_t *|buf|Buffer containing zip|
|int32_t|len|Length of buffer|
|int32_t|copy|Copy buffer internally if 1|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if opened.|

**Example**
```
uint8 *buffer = NULL;
int32 buffer_length = 0;
// TODO: Load zip file into memory buffer
mz_zip_reader_create(&zip_reader);
if (mz_zip_reader_open_buffer(zip_reader, buffer, buffer_length) == MZ_OK) {
    printf("Zip reader was opened from buffer\n");
    mz_zip_reader_close(zip_reader);
}
mz_zip_reader_delete(&zip_reader);
```

### mz_zip_reader_close

Closes the zip file.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful.|

**Example**
```
if (mz_zip_reader_close(zip_reader) == MZ_OK)
    printf("Zip reader closed\n");
```

## Reader Entry Enumeration

### mz_zip_reader_goto_first_entry

Goto the first entry in the zip file. If a pattern has been specified by calling _mz_zip_reader_set_pattern_, then it goes to the first entry matching the pattern.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful, MZ_END_OF_LIST if no more entries.|

**Example**
```
mz_zip_file *file_info = NULL;
if ((mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) &&
    (mz_zip_reader_entry_get_info(zip_reader, &file_info) == MZ_OK)) {
    printf("Zip first entry %s\n", file_info->filename);
}
```

### mz_zip_reader_goto_next_entry

Goto the next entry in the zip file. If a pattern has been specified by calling _mz_zip_reader_set_pattern_, then it goes to the next entry matching the pattern.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful, MZ_END_OF_LIST if no more entries.|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    do {
        mz_zip_file *file_info = NULL;
        if (mz_zip_reader_entry_get_info(zip_reader, &file_info) != MZ_OK) {
            printf("Unable to get zip entry info\n");
            break;
        }
        printf("Zip entry %s\n", file_info->filename);
    } while (mz_zip_reader_goto_next_entry(zip_reader) == MZ_OK);
}
```

### mz_zip_reader_locate_entry

Locates an entry by filename.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|filename|Filename to find|
|uint8_t|ignore_case|Ignore case during search if 1.|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful, MZ_END_OF_LIST if not found.|

**Example**
```
const char *search_filename = "test1.txt";
if (mz_zip_reader_locate_entry(zip_reader, search_filename, 1) == MZ_OK)
    printf("Found %s\n", search_filename);
else
    printf("Could not find %s\n", search_filename);
```

## Reader Entry

### mz_zip_reader_entry_open

Opens an entry for reading.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_open(zip_reader) == MZ_OK) {
        char buf[120];
        int32_t bytes_read = 0;
        bytes_read = mz_zip_reader_entry_read(zip_reader, buf, sizeof(buf));
        if (bytes_read > 0) {
            printf("Bytes read from entry %d\n", bytes_read);
        }
        mz_zip_reader_entry_close(zip_reader);
    }
}
```

### mz_zip_reader_entry_close

Closes an entry that has been opened for reading or writing.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
if (mz_zip_reader_entry_open(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_close(zip_reader) == MZ_OK) {
        printf("Entry closed successfully\n");
    }
}
```

### mz_zip_reader_entry_read

Reads an entry after being opened.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|buf|Buffer to read into|
|int32_t|len|Maximum length of buffer to read into|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_open(zip_reader) == MZ_OK) {
        char buf[120];
        int32_t bytes_read = 0;
        bytes_read = mz_zip_reader_entry_read(zip_reader, buf, sizeof(buf));
        if (bytes_read > 0) {
            printf("Bytes read from entry %d\n", bytes_read);
        }
        mz_zip_reader_entry_close(zip_reader);
    }
}
```

### mz_zip_reader_entry_has_sign

Checks to see if the entry has a signature.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if has signature.|

**Example**
```
if (mz_zip_reader_entry_has_sign(zip_reader) == MZ_OK)
    printf("Entry has signature attached\n");
```

### mz_zip_reader_entry_sign_verify

Verifies a signature stored with the entry.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if signature is valid.|

**Example**
```
if (mz_zip_reader_entry_has_sign(zip_reader) == MZ_OK) {
    printf("Entry has signature attached\n");
    if (mz_zip_reader_entry_sign_verify(zip_reader) == MZ_OK) {
        printf("Entry signature is valid\n);
    } else {
        printf("Entry signature is invalid\n");
    }
}
```

### mz_zip_reader_entry_get_hash

Gets a hash algorithm from the entry's extra field.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint16_t|algorithm|[MZ_HASH](mz_hash.md) algorithm identifier|
|uint8_t *|digest|Digest buffer|
|int32_t|digest_size|Maximum digest buffer size|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if hash found.|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    uint8_t sha1_digest[MZ_HASH_SHA1_SIZE];
    if (mz_zip_reader_entry_get_hash(zip_reader, MZ_HASH_SHA1, sha1_digest, sizeof(sha1_digest)) == MZ_OK) {
        printf("Found sha1 digest for entry\n");
    }
}
```

### mz_zip_reader_entry_get_first_hash

Gets the most secure hash algorithm from the entry's extra field.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint16_t *|algorithm|Pointer to store [MZ_HASH](mz_hash.md) algorithm identifier|
|uint16_t *|digest_size|Pointer to store digest size|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if hash found.|

**Example**
```
uint16_t algorithm = 0;
uint16_t digest_size = 0;
if (mz_zip_reader_entry_get_first_hash(zip_reader, &algorithm, &digest_size) == MZ_OK) {
    printf("Found hash: algo %d size %d\n", algorithm, digest_size);
}
```

### mz_zip_reader_entry_get_info

Gets the current entry file info.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|mz_zip_file **|file_info|Pointer to [mz_zip_file](mz_zip_file.md) structure|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_file *file_info = NULL;
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_get_info(zip_reader, &file_info) == MZ_OK) {
        printf("First entry: %s\n", file_info->filename);
    }
}
```

### mz_zip_reader_entry_is_dir

Gets the current entry is a directory.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_is_dir(zip_reader) == MZ_OK) {
        printf("Entry is a directory\n");
    }
}
```

### mz_zip_reader_entry_save

Save the current entry to a steam. Each time the function needs to write to the stream it will call the _mz_stream_write_cb_ callback with the _stream_ pointer. This is a blocking call that will not return until the entire entry is written to the stream or until an error has occured.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|stream|_mz_stream_ instance|
|mz_stream_write_cb|write_cb|Stream write callback|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
void *file_stream = NULL;
const char *path = "c:\\my.zip";
const char *entry_path = "c:\\entry.dat";

mz_zip_reader_create(&zip_reader);

err = mz_zip_reader_open_file(zip_reader, path);
if (err == MZ_OK) {
    printf("Zip reader was opened %s\n", path);
    err = mz_zip_reader_goto_first_entry(zip_reader);
    if (err == MZ_OK) {
        mz_stream_os_create(&entry_stream);
        err = mz_stream_os_open(entry_stream, entry_path, MZ_OPEN_MODE_WRITE);
        if (err == MZ_OK) {
            err = mz_zip_reader_entry_save(zip_reader, file_stream, mz_stream_os_write);
            mz_stream_os_close(entry_stream);
        }
        mz_stream_os_delete(&entry_stream);
    }
    mz_zip_reader_close(zip_reader);
}

mz_zip_reader_delete(&zip_reader);
```

### mz_zip_reader_entry_save_process

Saves a portion of the current entry to a stream. Each time the function is called it will read from the zip file once and then write the output to the _mz_stream_write_cb_ callback with _stream_ pointer. This is intended to be used when writing zip file in a process loop.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|stream|_mz_stream_ instance|
|mz_stream_write_cb|write_cb|Stream write callback|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if more to process, MZ_END_OF_STREAM if no more data to process.|

**Example**
```
int32_t err = MZ_OK;
// TODO: Open zip reader and entry stream.
while (1) {
    err = mz_zip_reader_entry_save_process(zip_reader, entry_stream, mz_stream_os_write);
    if (err != MZ_OK) {
        printf("There was an error writing to stream (%d)\n", err);
        break;
    }
    if (err == MZ_END_OF_STREAM) {
        printf("Finished writing to stream\n");
        break;
    }
}
```

### mz_zip_reader_entry_save_file

Save the current entry to a file.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|path|Path to save entry on disk|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    if (mz_zip_reader_entry_save_file(zip_reader, "entry1.bin") == MZ_OK) {
        printf("First entry saved to disk successfully\n");
    }
}
```

### mz_zip_reader_entry_save_buffer

Save the current entry to a memory buffer. To get the size required use _mz_zip_reader_entry_save_buffer_length_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|buf|Buffer to decompress to|
|int32_t|len|Maximum size of buffer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful, or MZ_BUF_ERROR if _buf_ is too small.|

**Example**
```
int32_t buf_size = (int32_t)mz_zip_reader_entry_save_buffer_length(zip_reader);
char *buf = (char *)malloc(buf_size);
int32_t err = mz_zip_reader_entry_save_buffer(zip_reader, buf, buf_size);
if (err == MZ_OK) {
    // TODO: Do something with buffer
}
free(buf);
```

### mz_zip_reader_entry_save_buffer_length

Gets the length of the buffer required to save.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
int32_t buf_size = (int32_t)mz_zip_reader_entry_save_buffer_length(zip_reader);
char *buf = (char *)malloc(buf_size);
int32_t err = mz_zip_reader_entry_save_buffer(zip_reader, buf, buf_size);
if (err == MZ_OK) {
    // TODO: Do something with buffer
}
free(buf);
```

## Reader Bulk Extract

### mz_zip_reader_save_all

Save all files into a directory.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|destination_dir|Directory to extract all files to|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
const char *destination_dir = "c:\\temp\\";
if (mz_zip_reader_save_all(zip_reader, destination_dir) == MZ_OK) {
    printf("All files successfully saved to %s\n", destination_dir);
}
```

## Reader Object

### mz_zip_reader_set_pattern

Sets the match pattern for entries in the zip file, if null all entries are matched. This match pattern is used when calling _mz_zip_reader_goto_first_entry_ and _mz_zip_reader_goto_next_entry_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|pattern|Search pattern or NULL if not used|
|uint8_t|ignore_case|Ignore case when matching if 1|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
int32_t matches = 0;
const char *pattern = "*.txt";
mz_zip_reader_set_pattern(zip_reader, pattern, 1);
if (mz_zip_reader_goto_first_entry(zip_reader) == MZ_OK) {
    do {
        matches += 1;
    } while (mz_zip_reader_goto_next_entry(zip_reader) == MZ_OK);
}
printf("Found %d zip entries matching pattern %s\n", matches, pattern);
```

### mz_zip_reader_set_password

Sets the password required for extracting entire zip file. If not specified, then _mz_zip_reader_password_cb_ will be called for password protected zip entries.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char *|password|Password to use for entire zip file|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_reader_set_password(zip_handle, "mypassword");
```

### mz_zip_reader_set_raw

Sets whether or not it should save the entry raw.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint8_t|raw|Save entry as raw data if 1|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_reader_set_raw(zip_reader, 1);
```

### mz_zip_reader_get_raw

Gets whether or not it should save the entry raw.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint8_t *|raw|Pointer to store if saving as raw data|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
uint8_t raw = 0;
mz_zip_reader_get_raw(zip_reader, &raw);
printf("Entry will be saved as %s data\n", (raw) ? "raw gzip" : "decompressed");
```

### mz_zip_reader_get_zip_cd

Gets whether or not the archive has a zipped central directory.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint8_t *|zip_cd|Pointer to store if central directory is zipped|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
uint8_t zip_cd = 0;
mz_zip_reader_get_zip_cd(zip_reader, &zip_cd);
printf("Central directory %s zipped\n", (zip_cd) ? "is" : "is not");
```

### mz_zip_reader_get_comment

Gets the comment for the central directory.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|const char **|comment|Pointer to store global comment pointer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
const char *global_comment = NULL;
if (mz_zip_reader_get_comment(zip_reader, &global_comment) == MZ_OK) {
    printf("Zip comment: %s\n", global_comment);
}
```

### mz_zip_reader_set_encoding

Sets whether or not it should support a special character encoding in zip file names.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|int32_t|encoding|[MZ_ENCODING](mz_encoding.md) identifier|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_reader_set_encoding(zip_reader, MZ_ENCODING_CODEPAGE_437);
```

### mz_zip_reader_set_sign_required

Sets whether or not it a signature is required. If enabled, it will prevent extraction of zip entries that do not have verified signatures.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint8_t|sign_required|Valid CMS signatures are required if 1|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_reader_set_sign_required(zip_reader, 1);
```

### mz_zip_reader_set_overwrite_cb

Sets the callback for what to do when a file is about to be overwritten.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|User supplied data|
|mz_zip_reader_overwrite_cb|cb|_mz_zip_reader_overwrite_cb_ function pointer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See example for _mz_zip_reader_overwrite_cb_.

### mz_zip_reader_set_password_cb

Sets the callback for what to do when a password is required and hasn't been set.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|User supplied data|
|mz_zip_reader_password_cb|cb|_mz_zip_reader_password_cb_ function pointer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See example for _mz_zip_reader_password_cb_.

### mz_zip_reader_set_progress_cb

Sets the callback that gets called to update extraction progress. This callback is called on an interval specified by _mz_zip_reader_set_progress_interval_.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|User supplied data|
|mz_zip_reader_progress_cb|cb|_mz_zip_reader_progress_cb_ function pointer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See example for _mz_zip_reader_progress_cb_.

### mz_zip_reader_set_progress_interval

Let at least milliseconds pass between calls to progress callback.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|uint32_t|milliseconds|Number of milliseconds to wait before calling _mz_zip_reader_progress_cb_ during extraction|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
mz_zip_reader_set_progress_interval(zip_reader, 1000); // Wait 1 sec
```

### mz_zip_reader_set_entry_cb

Sets callback for when a new zip file entry is encountered during extraction.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void *|userdata|User supplied data|
|mz_zip_reader_entry_cb|cb|_mz_zip_reader_entry_cb_ function pointer|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**

See example for _mz_zip_reader_entry_cb_.

### mz_zip_reader_get_zip_handle

Gets the underlying zip instance handle.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void *|handle|_mz_zip_reader_ instance|
|void **|zip_handle|Pointer to store _mz_zip_ instance|

**Return**
|Type|Description|
|-|-|
|int32_t|[MZ_ERROR](mz_error.md) code, MZ_OK if successful|

**Example**
```
void *zip_handle = NULL;
mz_zip_reader_get_zip_handle(zip_reader, &zip_handle);
mz_zip_goto_first_entry(zip_handle);
```

### mz_zip_reader_create

Creates a _mz_zip_reader_ instance and returns its pointer.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void **|handle|Pointer to store the _mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|void *|Pointer to the _mz_zip_reader_ instance|

**Example**
```
void *zip_reader = NULL;
mz_zip_reader_create(&zip_reader);
```

### mz_zip_reader_delete

Deletes a _mz_zip_reader_ instance and resets its pointer to zero.

**Arguments**
|Type|Name|Description|
|-|-|-|
|void **|handle|Pointer to the _mz_zip_reader_ instance|

**Return**
|Type|Description|
|-|-|
|void|No return|

**Example**
```
void *zip_reader = NULL;
mz_zip_reader_create(&zip_reader);
mz_zip_reader_delete(&zip_reader);
```
