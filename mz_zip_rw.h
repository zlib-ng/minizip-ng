/* mz_zip_rw.h -- Zip reader/writer
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_ZIP_RW_H
#define MZ_ZIP_RW_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

typedef int32_t (*mz_zip_reader_overwrite_cb)(void *handle, void *userdata, mz_zip_file *file_info, const char *path);
typedef int32_t (*mz_zip_reader_password_cb)(void *handle, void *userdata, mz_zip_file *file_info, char *password,
                                             int32_t max_password);
typedef int32_t (*mz_zip_reader_progress_cb)(void *handle, void *userdata, mz_zip_file *file_info, int64_t position);
typedef int32_t (*mz_zip_reader_entry_cb)(void *handle, void *userdata, mz_zip_file *file_info, const char *path);

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_reader_is_open(void *handle);
/* Checks to see if the zip file is open */

MZ_EXPORT int32_t mz_zip_reader_open(void *handle, void *stream);
/* Opens zip file from stream */

MZ_EXPORT int32_t mz_zip_reader_open_file(void *handle, const char *path);
/* Opens zip file from a file path */

MZ_EXPORT int32_t mz_zip_reader_open_file_in_memory(void *handle, const char *path);
/* Opens zip file from a file path into memory for faster access */

MZ_EXPORT int32_t mz_zip_reader_open_buffer(void *handle, const uint8_t *buf, int32_t len, uint8_t copy);
/* Opens zip file from memory buffer */

MZ_EXPORT int32_t mz_zip_reader_close(void *handle);
/* Closes the zip file */

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_reader_unzip_cd(void *handle);
/* Unzip the central directory */

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_reader_goto_first_entry(void *handle);
/* Goto the first entry in the zip file that matches the pattern */

MZ_EXPORT int32_t mz_zip_reader_goto_next_entry(void *handle);
/* Goto the next entry in the zip file that matches the pattern */

MZ_EXPORT int32_t mz_zip_reader_locate_entry(void *handle, const char *filename, uint8_t ignore_case);
/* Locates an entry by filename */

MZ_EXPORT int32_t mz_zip_reader_entry_open(void *handle);
/* Opens an entry for reading */

MZ_EXPORT int32_t mz_zip_reader_entry_close(void *handle);
/* Closes an entry */

MZ_EXPORT int32_t mz_zip_reader_entry_read(void *handle, void *buf, int32_t len);
/* Reads an entry after being opened */

MZ_EXPORT int32_t mz_zip_reader_entry_get_hash(void *handle, uint16_t algorithm, uint8_t *digest, int32_t digest_size);
/* Gets a hash algorithm from the entry's extra field */

MZ_EXPORT int32_t mz_zip_reader_entry_get_first_hash(void *handle, uint16_t *algorithm, uint16_t *digest_size);
/* Gets the most secure hash algorithm from the entry's extra field */

MZ_EXPORT int32_t mz_zip_reader_entry_get_info(void *handle, mz_zip_file **file_info);
/* Gets the current entry file info */

MZ_EXPORT int32_t mz_zip_reader_entry_is_dir(void *handle);
/* Gets the current entry is a directory */

MZ_EXPORT int32_t mz_zip_reader_entry_save(void *handle, void *stream, mz_stream_write_cb write_cb);
/* Save the current entry to a stream */

MZ_EXPORT int32_t mz_zip_reader_entry_save_process(void *handle, void *stream, mz_stream_write_cb write_cb);
/* Saves a portion of the current entry to a stream callback */

MZ_EXPORT int32_t mz_zip_reader_entry_save_file(void *handle, const char *path);
/* Save the current entry to a file */

MZ_EXPORT int32_t mz_zip_reader_entry_save_buffer(void *handle, void *buf, int32_t len);
/* Save the current entry to a memory buffer */

MZ_EXPORT int32_t mz_zip_reader_entry_save_buffer_length(void *handle);
/* Gets the length of the buffer required to save */

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_reader_save_all(void *handle, const char *destination_dir);
/* Save all files into a directory */

/***************************************************************************/

MZ_EXPORT void mz_zip_reader_set_pattern(void *handle, const char *pattern, uint8_t ignore_case);
/* Sets the match pattern for entries in the zip file, if null all entries are matched */

MZ_EXPORT void mz_zip_reader_set_password(void *handle, const char *password);
/* Sets the password required for extraction */

MZ_EXPORT void mz_zip_reader_set_raw(void *handle, uint8_t raw);
/* Sets whether or not it should save the entry raw */

MZ_EXPORT int32_t mz_zip_reader_get_raw(void *handle, uint8_t *raw);
/* Gets whether or not it should save the entry raw */

MZ_EXPORT int32_t mz_zip_reader_get_zip_cd(void *handle, uint8_t *zip_cd);
/* Gets whether or not the archive has a zipped central directory */

MZ_EXPORT int32_t mz_zip_reader_get_comment(void *handle, const char **comment);
/* Gets the comment for the central directory */

MZ_EXPORT int32_t mz_zip_reader_set_recover(void *handle, uint8_t recover);
/* Sets the ability to recover the central dir by reading local file headers */

MZ_EXPORT void mz_zip_reader_set_encoding(void *handle, int32_t encoding);
/* Sets whether or not it should support a special character encoding in zip file names. */

MZ_EXPORT void mz_zip_reader_set_overwrite_cb(void *handle, void *userdata, mz_zip_reader_overwrite_cb cb);
/* Callback for what to do when a file is being overwritten */

MZ_EXPORT void mz_zip_reader_set_password_cb(void *handle, void *userdata, mz_zip_reader_password_cb cb);
/* Callback for when a password is required and hasn't been set */

MZ_EXPORT void mz_zip_reader_set_progress_cb(void *handle, void *userdata, mz_zip_reader_progress_cb cb);
/* Callback for extraction progress */

MZ_EXPORT void mz_zip_reader_set_progress_interval(void *handle, uint32_t milliseconds);
/* Let at least milliseconds pass between calls to progress callback */

MZ_EXPORT void mz_zip_reader_set_entry_cb(void *handle, void *userdata, mz_zip_reader_entry_cb cb);
/* Callback for zip file entries */

MZ_EXPORT int32_t mz_zip_reader_get_zip_handle(void *handle, void **zip_handle);
/* Gets the underlying zip instance handle */

MZ_EXPORT void *mz_zip_reader_create(void);
/* Create new instance of zip reader */

MZ_EXPORT void mz_zip_reader_delete(void **handle);
/* Delete instance of zip reader */

/***************************************************************************/

typedef int32_t (*mz_zip_writer_overwrite_cb)(void *handle, void *userdata, const char *path);
typedef int32_t (*mz_zip_writer_password_cb)(void *handle, void *userdata, mz_zip_file *file_info, char *password,
                                             int32_t max_password);
typedef int32_t (*mz_zip_writer_progress_cb)(void *handle, void *userdata, mz_zip_file *file_info, int64_t position);
typedef int32_t (*mz_zip_writer_entry_cb)(void *handle, void *userdata, mz_zip_file *file_info);

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_writer_is_open(void *handle);
/* Checks to see if the zip file is open */

MZ_EXPORT int32_t mz_zip_writer_open(void *handle, void *stream, uint8_t append);
/* Opens zip file from stream */

MZ_EXPORT int32_t mz_zip_writer_open_file(void *handle, const char *path, int64_t disk_size, uint8_t append);
/* Opens zip file from a file path */

MZ_EXPORT int32_t mz_zip_writer_open_file_in_memory(void *handle, const char *path);
/* Opens zip file from a file path into memory for faster access */

MZ_EXPORT int32_t mz_zip_writer_close(void *handle);
/* Closes the zip file */

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_writer_entry_open(void *handle, mz_zip_file *file_info);
/* Opens an entry in the zip file for writing */

MZ_EXPORT int32_t mz_zip_writer_entry_close(void *handle);
/* Closes entry in zip file */

MZ_EXPORT int32_t mz_zip_writer_entry_write(void *handle, const void *buf, int32_t len);
/* Writes data into entry for zip */

/***************************************************************************/

MZ_EXPORT int32_t mz_zip_writer_add(void *handle, void *stream, mz_stream_read_cb read_cb);
/* Writes all data to the currently open entry in the zip */

MZ_EXPORT int32_t mz_zip_writer_add_process(void *handle, void *stream, mz_stream_read_cb read_cb);
/* Writes a portion of data to the currently open entry in the zip */

MZ_EXPORT int32_t mz_zip_writer_add_info(void *handle, void *stream, mz_stream_read_cb read_cb, mz_zip_file *file_info);
/* Adds an entry to the zip based on the info */

MZ_EXPORT int32_t mz_zip_writer_add_buffer(void *handle, const void *buf, int32_t len, mz_zip_file *file_info);
/* Adds an entry to the zip with a memory buffer */

MZ_EXPORT int32_t mz_zip_writer_add_file(void *handle, const char *path, const char *filename_in_zip);
/* Adds an entry to the zip from a file */

MZ_EXPORT int32_t mz_zip_writer_add_path(void *handle, const char *path, const char *root_path, uint8_t include_path,
                                         uint8_t recursive);
/* Enumerates a directory or pattern and adds entries to the zip */

MZ_EXPORT int32_t mz_zip_writer_copy_from_reader(void *handle, void *reader);
/* Adds an entry from a zip reader instance */

/***************************************************************************/

MZ_EXPORT void mz_zip_writer_set_password(void *handle, const char *password);
/* Password to use for encrypting files in the zip */

MZ_EXPORT void mz_zip_writer_set_comment(void *handle, const char *comment);
/* Comment to use for the archive */

MZ_EXPORT void mz_zip_writer_set_raw(void *handle, uint8_t raw);
/* Sets whether or not we should write the entry raw */

MZ_EXPORT int32_t mz_zip_writer_get_raw(void *handle, uint8_t *raw);
/* Gets whether or not we should write the entry raw */

MZ_EXPORT void mz_zip_writer_set_aes(void *handle, uint8_t aes);
/* Use aes encryption when adding files in zip */

MZ_EXPORT void mz_zip_writer_set_compress_method(void *handle, uint16_t compress_method);
/* Sets the compression method when adding files in zip */

MZ_EXPORT void mz_zip_writer_set_compress_level(void *handle, int16_t compress_level);
/* Sets the compression level when adding files in zip */

MZ_EXPORT void mz_zip_writer_set_follow_links(void *handle, uint8_t follow_links);
/* Follow symbolic links when traversing directories and files to add */

MZ_EXPORT int32_t mz_zip_writer_get_follow_links(void *handle, uint8_t *follow_links);
/* Gets whether to follow symbolic links when traversing directories and files to add */

MZ_EXPORT void mz_zip_writer_set_store_links(void *handle, uint8_t store_links);
/* Store symbolic links in zip file */

MZ_EXPORT void mz_zip_writer_set_zip_cd(void *handle, uint8_t zip_cd);
/* Sets whether or not central directory should be zipped */

MZ_EXPORT int32_t mz_zip_writer_set_certificate(void *handle, const char *cert_path, const char *cert_pwd);
/* Sets the certificate and timestamp url to use for signing when adding files in zip */

MZ_EXPORT void mz_zip_writer_set_overwrite_cb(void *handle, void *userdata, mz_zip_writer_overwrite_cb cb);
/* Callback for what to do when zip file already exists */

MZ_EXPORT void mz_zip_writer_set_password_cb(void *handle, void *userdata, mz_zip_writer_password_cb cb);
/* Callback for ask if a password is required for adding */

MZ_EXPORT void mz_zip_writer_set_progress_cb(void *handle, void *userdata, mz_zip_writer_progress_cb cb);
/* Callback for compression progress */

MZ_EXPORT void mz_zip_writer_set_progress_interval(void *handle, uint32_t milliseconds);
/* Let at least milliseconds pass between calls to progress callback */

MZ_EXPORT void mz_zip_writer_set_entry_cb(void *handle, void *userdata, mz_zip_writer_entry_cb cb);
/* Callback for zip file entries */

MZ_EXPORT int32_t mz_zip_writer_get_zip_handle(void *handle, void **zip_handle);
/* Gets the underlying zip handle */

MZ_EXPORT void *mz_zip_writer_create(void);
/* Create new instance of zip writer */

MZ_EXPORT void mz_zip_writer_delete(void **handle);
/* Delete instance of zip writer */

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
