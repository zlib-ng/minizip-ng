/* mz_zip_rw.c -- Zip reader/writer
   Version 2.5.1, August 18, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_buf.h"
#include "mz_strm_mem.h"
#include "mz_strm_split.h"
#include "mz_zip.h"

#include "mz_zip_rw.h"

/***************************************************************************/

typedef struct mz_zip_reader_s {
    void        *zip_handle;
    void        *file_stream;
    void        *buffered_stream;
    void        *split_stream;
    void        *mem_stream;
    mz_zip_file *file_info;
    const char  *pattern;
    uint8_t     pattern_ignore_case;
    const char  *password;
    void        *overwrite_userdata;
    mz_zip_reader_overwrite_cb
                overwrite_cb;
    void        *password_userdata;
    mz_zip_reader_password_cb
                password_cb;
    void        *progress_userdata;
    mz_zip_reader_progress_cb
                progress_cb;
    void        *entry_userdata;
    mz_zip_reader_entry_cb
                entry_cb;
    uint8_t     raw;
    uint8_t     buffer[UINT16_MAX];
} mz_zip_reader;

/***************************************************************************/

int32_t mz_zip_reader_is_open(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    if (reader == NULL)
        return MZ_PARAM_ERROR;
    if (reader->zip_handle == NULL)
        return MZ_PARAM_ERROR;
    return MZ_OK;
}

int32_t mz_zip_reader_open(void *handle, void *stream)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    mz_zip_create(&reader->zip_handle);
    err = mz_zip_open(reader->zip_handle, stream, MZ_OPEN_MODE_READ);

    if (err != MZ_OK)
    {
        mz_zip_reader_close(handle);
        return MZ_STREAM_ERROR;
    }

    return MZ_OK;
}

int32_t mz_zip_reader_open_file(void *handle, const char *path)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;


    mz_zip_reader_close(handle);

    mz_stream_os_create(&reader->file_stream);
    mz_stream_buffered_create(&reader->buffered_stream);
    mz_stream_split_create(&reader->split_stream);

    mz_stream_set_base(reader->buffered_stream, reader->file_stream);
    mz_stream_set_base(reader->split_stream, reader->buffered_stream);

    err = mz_stream_open(reader->split_stream, path, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
        err = mz_zip_reader_open(handle, reader->split_stream);

    return err;
}

int32_t mz_zip_reader_open_file_in_memory(void *handle, const char *path)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    void *file_stream = NULL;
    int64_t file_size = 0;
    int32_t err = 0;


    mz_zip_reader_close(handle);

    mz_stream_os_create(&file_stream);

    err = mz_stream_os_open(file_stream, path, MZ_OPEN_MODE_READ);

    if (err != MZ_OK)
    {
        mz_stream_os_delete(&file_stream);
        mz_zip_reader_close(handle);
        return err;
    }

    mz_stream_os_seek(file_stream, 0, SEEK_END);
    file_size = mz_stream_os_tell(file_stream);
    mz_stream_os_seek(file_stream, 0, SEEK_SET);

    if ((file_size <= 0) || (file_size > UINT32_MAX))
    {
        // Memory size is too large or too small

        mz_stream_os_close(file_stream);
        mz_stream_os_delete(&file_stream);
        mz_zip_reader_close(handle);
        return MZ_MEM_ERROR;
    }

    mz_stream_mem_create(&reader->mem_stream);
    mz_stream_mem_set_grow_size(reader->mem_stream, (int32_t)file_size);
    mz_stream_mem_open(reader->mem_stream, NULL, MZ_OPEN_MODE_CREATE);

    err = mz_stream_copy(reader->mem_stream, file_stream, (int32_t)file_size);

    mz_stream_os_close(file_stream);
    mz_stream_os_delete(&file_stream);

    if (err == MZ_OK)
        err = mz_zip_reader_open(handle, reader->mem_stream);
    if (err != MZ_OK)
        mz_zip_reader_close(handle);

    return err;
}

int32_t mz_zip_reader_open_buffer(void *handle, uint8_t *buf, int32_t len, uint8_t copy)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    mz_zip_reader_close(handle);

    mz_stream_mem_create(&reader->mem_stream);

    if (copy)
    {
        mz_stream_mem_set_grow_size(reader->mem_stream, len);
        mz_stream_mem_open(reader->mem_stream, NULL, MZ_OPEN_MODE_CREATE);
        mz_stream_mem_write(reader->mem_stream, buf, len);
        mz_stream_mem_seek(reader->mem_stream, 0, SEEK_SET);
    }
    else
    {
        mz_stream_mem_open(reader->mem_stream, NULL, MZ_OPEN_MODE_READ);
        mz_stream_mem_set_buffer(reader->mem_stream, buf, len);
    }

    if (err == MZ_OK)
        err = mz_zip_reader_open(handle, reader->mem_stream);

    return err;
}

int32_t mz_zip_reader_close(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    if (reader->zip_handle != NULL)
    {
        err = mz_zip_close(reader->zip_handle);
        mz_zip_delete(&reader->zip_handle);
    }

    if (reader->split_stream != NULL)
    {
        mz_stream_split_close(reader->split_stream);
        mz_stream_split_delete(&reader->split_stream);
    }

    if (reader->buffered_stream != NULL)
        mz_stream_buffered_delete(&reader->buffered_stream);

    if (reader->file_stream != NULL)
        mz_stream_os_delete(&reader->file_stream);

    if (reader->mem_stream != NULL)
    {
        mz_stream_mem_close(reader->mem_stream);
        mz_stream_mem_delete(&reader->mem_stream);
    }

    return err;
}

/***************************************************************************/

static int32_t mz_zip_reader_locate_entry_cb(void *handle, void *userdata, mz_zip_file *file_info)
{
    mz_zip_reader *reader = (mz_zip_reader *)userdata;
    int32_t result = 0;
    result = mz_path_compare_wc(file_info->filename, reader->pattern, reader->pattern_ignore_case);
    return result;
}

int32_t mz_zip_reader_goto_first_entry(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    if (mz_zip_reader_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;

    if (mz_zip_entry_is_open(reader->zip_handle) == MZ_OK)
        mz_zip_reader_entry_close(handle);

    if (reader->pattern == NULL)
        err = mz_zip_goto_first_entry(reader->zip_handle);
    else
        err = mz_zip_locate_first_entry(reader->zip_handle, reader, mz_zip_reader_locate_entry_cb);

    reader->file_info = NULL;
    if (err == MZ_OK)
        err = mz_zip_entry_get_info(reader->zip_handle, &reader->file_info);

    return err;
}

int32_t mz_zip_reader_goto_next_entry(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    if (mz_zip_reader_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;

    if (mz_zip_entry_is_open(reader->zip_handle) == MZ_OK)
        mz_zip_reader_entry_close(handle);

    if (reader->pattern == NULL)
        err = mz_zip_goto_next_entry(reader->zip_handle);
    else
        err = mz_zip_locate_next_entry(reader->zip_handle, reader, mz_zip_reader_locate_entry_cb);

    reader->file_info = NULL;
    if (err == MZ_OK)
        err = mz_zip_entry_get_info(reader->zip_handle, &reader->file_info);

    return err;
}

int32_t mz_zip_reader_locate_entry(void *handle, const char *filename, uint8_t ignore_case)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;

    if (mz_zip_entry_is_open(reader->zip_handle) == MZ_OK)
        mz_zip_reader_entry_close(handle);

    err = mz_zip_locate_entry(reader->zip_handle, filename, ignore_case);

    reader->file_info = NULL;
    if (err == MZ_OK)
        err = mz_zip_entry_get_info(reader->zip_handle, &reader->file_info);

    return err;
}

/***************************************************************************/

int32_t mz_zip_reader_entry_open(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;
    const char *password = NULL;
    char password_buf[120];


    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL)
        return MZ_PARAM_ERROR;

    // If the entry isn't open for reading, open it
    if (mz_zip_entry_is_open(reader->zip_handle) != MZ_OK)
    {
        password = reader->password;

        // Check if we need a password and ask for it if we need to
        if ((reader->file_info->flag & MZ_ZIP_FLAG_ENCRYPTED) && (password == NULL) &&
            (reader->password_cb != NULL))
        {
            reader->password_cb(handle, reader->password_userdata, reader->file_info, password_buf, sizeof(password_buf));
            password = password_buf;
        }

        err = mz_zip_entry_read_open(reader->zip_handle, reader->raw, password);
    }

    return err;
}

int32_t mz_zip_reader_entry_close(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;
    err = mz_zip_entry_close(reader->zip_handle);
    return err;
}

int32_t mz_zip_reader_entry_read(void *handle, const void *buf, int32_t len)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t read = 0;
    read = mz_zip_entry_read(reader->zip_handle, (void *)buf, len);
    return read;
}

int32_t mz_zip_reader_entry_get_info(void *handle, mz_zip_file **file_info)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;
    if (file_info == NULL || mz_zip_reader_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;
    *file_info = reader->file_info;
    if (*file_info == NULL)
        return MZ_EXIST_ERROR;
    return err;
}

int32_t mz_zip_reader_entry_save_process(void *handle, void *stream, mz_stream_write_cb write_cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;
    int32_t read = 0;
    int32_t written = 0;


    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL)
        return MZ_PARAM_ERROR;
    if (write_cb == NULL)
        return MZ_PARAM_ERROR;

    // If the entry isn't open for reading, open it
    if (mz_zip_entry_is_open(reader->zip_handle) != MZ_OK)
        err = mz_zip_reader_entry_open(handle);

    if (err != MZ_OK)
        return err;

    // Unzip entry in zip file
    read = mz_zip_reader_entry_read(handle, reader->buffer, sizeof(reader->buffer));

    if (read == 0)
    {
        // If we are done close the entry
        err = mz_zip_reader_entry_close(handle);
        if (err != MZ_OK)
            return err;

        return MZ_END_OF_STREAM;
    }

    if (read > 0)
    {
        // Write the data to the specified stream
        written = write_cb(stream, reader->buffer, read);
        if (written != read)
            return MZ_STREAM_ERROR;
    }

    return read;
}

int32_t mz_zip_reader_entry_save(void *handle, void *stream, mz_stream_write_cb write_cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int64_t current_pos = 0;
    int64_t update_pos = 0;
    int32_t err = MZ_OK;
    int32_t written = 0;
    time_t current_time = time(NULL);
    time_t update_time = 0;

    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL)
        return MZ_PARAM_ERROR;

    // Update the progress at the beginning
    if (reader->progress_cb != NULL)
        reader->progress_cb(handle, reader->progress_userdata, reader->file_info, current_pos);

    // Write data to stream until done
    while (err == MZ_OK)
    {
        written = mz_zip_reader_entry_save_process(handle, stream, write_cb);
        if (written == MZ_END_OF_STREAM)
            break;
        if (written > 0)
            current_pos += written;
        if (written < 0)
            err = written;

        // Every 1 second lets update the progress 
        current_time = time(NULL);
        if ((current_time - update_time) > 1)
        {
            if (reader->progress_cb != NULL)
                reader->progress_cb(handle, reader->progress_userdata, reader->file_info, current_pos);

            update_pos = current_pos;
            update_time = current_time;
        }
    }

    // Update the progress at the end
    if (reader->progress_cb != NULL && update_pos != current_pos)
        reader->progress_cb(handle, reader->progress_userdata, reader->file_info, current_pos);

    return err;
}

int32_t mz_zip_reader_entry_save_file(void *handle, const char *path)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    void *file_stream = NULL;
    int32_t err = MZ_OK;
    int32_t err_cb = MZ_OK;
    char directory[512];

    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL || path == NULL)
        return MZ_PARAM_ERROR;

    if (reader->entry_cb != NULL)
        reader->entry_cb(handle, reader->entry_userdata, reader->file_info, path);

    strncpy(directory, path, sizeof(directory));
    mz_path_remove_filename(directory);

    // If it is a directory entry then create a directory instead of writing file
    if (mz_zip_entry_is_dir(reader->zip_handle) == MZ_OK)
    {
        err = mz_make_dir(directory);
        return err;
    }

    // Check if file exists and ask if we want to overwrite
    if ((mz_os_file_exists(path) == MZ_OK) && (reader->overwrite_cb != NULL))
    {
        err_cb = reader->overwrite_cb(handle, reader->overwrite_userdata, reader->file_info, path);
        if (err_cb != MZ_OK)
            return err;
    }

    // Create the output directory if it doesn't already exist
    if (mz_os_is_dir(directory) != MZ_OK)
    {
        err = mz_make_dir(directory);
        if (err != MZ_OK)
            return err;
    }

    mz_stream_os_create(&file_stream);

    // Create the file on disk so we can save to it
    err = mz_stream_os_open(file_stream, path, MZ_OPEN_MODE_CREATE);

    if (err == MZ_OK)
        err = mz_zip_reader_entry_save(handle, file_stream, mz_stream_os_write);

    mz_stream_os_close(file_stream);
    mz_stream_os_delete(&file_stream);

    if (err == MZ_OK)
    {
        // Set the time of the file that has been created
        mz_os_set_file_date(path, reader->file_info->modified_date, 
            reader->file_info->accessed_date, reader->file_info->creation_date);
    }

    return err;
}

int32_t mz_zip_reader_entry_save_buffer(void *handle, void *buf, int32_t len)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    void *mem_stream = NULL;
    int32_t err = MZ_OK;

    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL)
        return MZ_PARAM_ERROR;
    if (reader->file_info->uncompressed_size > INT32_MAX)
        return MZ_PARAM_ERROR;
    if (len != (int32_t)reader->file_info->uncompressed_size)
        return MZ_PARAM_ERROR;

    // Create a memory stream backed by our buffer and save to it 
    mz_stream_mem_create(&mem_stream);
    mz_stream_mem_set_buffer(mem_stream, buf, len);

    err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
        err = mz_zip_reader_entry_save(handle, mem_stream, mz_stream_mem_write);

    mz_stream_mem_delete(&mem_stream);
    return err;
}

int32_t mz_zip_reader_entry_save_buffer_length(void *handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;

    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (reader->file_info == NULL)
        return MZ_PARAM_ERROR;
    if (reader->file_info->uncompressed_size > INT32_MAX)
        return MZ_PARAM_ERROR;

    // Get the maximum size required for the save buffer
    return (int32_t)reader->file_info->uncompressed_size;
}

/***************************************************************************/

int32_t mz_zip_reader_save_all(void *handle, const char *destination_dir)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    int32_t err = MZ_OK;
    char path[512];
    char resolved_name[256];

    err = mz_zip_reader_goto_first_entry(handle);

    while (err == MZ_OK)
    {
        // Construct output path
        path[0] = 0;

        err = mz_path_resolve(reader->file_info->filename, resolved_name, sizeof(resolved_name));
        if (err != MZ_OK)
            break;

        if (destination_dir != NULL)
            mz_path_combine(path, destination_dir, sizeof(path));

        mz_path_combine(path, resolved_name, sizeof(path));

        // Save file to disk
        err = mz_zip_reader_entry_save_file(handle, path);

        if (err == MZ_OK)
            err = mz_zip_reader_goto_next_entry(handle);
    }

    if (err == MZ_END_OF_LIST)
        return MZ_OK;

    return err;
}

/***************************************************************************/

void mz_zip_reader_set_pattern(void *handle, const char *pattern, uint8_t ignore_case)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->pattern = pattern;
    reader->pattern_ignore_case = ignore_case;
}

void mz_zip_reader_set_password(void *handle, const char *password)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->password = password;
}

void mz_zip_reader_set_raw(void *handle, uint8_t raw)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->raw = raw;
}

int32_t mz_zip_reader_get_raw(void *handle, uint8_t *raw)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    if (raw == NULL)
        return MZ_PARAM_ERROR;
    *raw = reader->raw;
    return MZ_OK;
}

void mz_zip_reader_set_overwrite_cb(void *handle, void *userdata, mz_zip_reader_overwrite_cb cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->overwrite_cb = cb;
    reader->overwrite_userdata = userdata;
}

void mz_zip_reader_set_password_cb(void *handle, void *userdata, mz_zip_reader_password_cb cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->password_cb = cb;
    reader->password_userdata = userdata;
}

void mz_zip_reader_set_progress_cb(void *handle, void *userdata, mz_zip_reader_progress_cb cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->progress_cb = cb;
    reader->progress_userdata = userdata;
}

void mz_zip_reader_set_entry_cb(void *handle, void *userdata, mz_zip_reader_entry_cb cb)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    reader->entry_cb = cb;
    reader->entry_userdata = userdata;
}

int32_t mz_zip_reader_get_zip_handle(void *handle, void **zip_handle)
{
    mz_zip_reader *reader = (mz_zip_reader *)handle;
    if (zip_handle == NULL)
        return MZ_PARAM_ERROR;
    *zip_handle = reader->zip_handle;
    if (*zip_handle == NULL)
        return MZ_EXIST_ERROR;
    return MZ_OK;
}

/***************************************************************************/

void *mz_zip_reader_create(void **handle)
{
    mz_zip_reader *reader = NULL;

    reader = (mz_zip_reader *)MZ_ALLOC(sizeof(mz_zip_reader));
    if (reader != NULL)
    {
        memset(reader, 0, sizeof(mz_zip_reader));
    }
    if (reader != NULL)
        *handle = reader;

    return reader;
}

void mz_zip_reader_delete(void **handle)
{
    mz_zip_reader *reader = NULL;
    if (handle == NULL)
        return;
    reader = (mz_zip_reader *)*handle;
    if (reader != NULL)
    {
        mz_zip_reader_close(reader);
        MZ_FREE(reader);
    }
    *handle = NULL;
}

/***************************************************************************/

typedef struct mz_zip_writer_s {
    void        *zip_handle;
    void        *file_stream;
    void        *buffered_stream;
    void        *split_stream;
    void        *mem_stream;
    mz_zip_file file_info;
    void        *overwrite_userdata;
    mz_zip_writer_overwrite_cb
                overwrite_cb;
    void        *password_userdata;
    mz_zip_writer_password_cb
                password_cb;
    void        *progress_userdata;
    mz_zip_writer_progress_cb
                progress_cb;
    void        *entry_userdata;
    mz_zip_writer_entry_cb
                entry_cb;
    const char  *password;
    int16_t     compress_method;
    int16_t     compress_level;
    uint8_t     aes;
    uint8_t     raw;
    uint8_t     buffer[UINT16_MAX];
} mz_zip_writer;

/***************************************************************************/

int32_t mz_zip_writer_is_open(void *handle)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    if (writer == NULL)
        return MZ_PARAM_ERROR;
    if (writer->zip_handle == NULL)
        return MZ_PARAM_ERROR;
    return MZ_OK;
}

static int32_t mz_zip_writer_open_int(void *handle, void *stream, int32_t mode)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t err = MZ_OK;

    mz_zip_create(&writer->zip_handle);
    err = mz_zip_open(writer->zip_handle, stream, mode);

    if (err != MZ_OK)
    {
        mz_zip_writer_close(handle);
        return MZ_STREAM_ERROR;
    }

    return MZ_OK;
}

int32_t mz_zip_writer_open(void *handle, void *stream)
{
    return mz_zip_writer_open_int(handle, stream, 0);
}

int32_t mz_zip_writer_open_file(void *handle, const char *path, int64_t disk_size, uint8_t append)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t mode = MZ_OPEN_MODE_READWRITE;
    int32_t err = MZ_OK;
    int32_t err_cb = 0;


    mz_zip_writer_close(handle);

    if (mz_os_file_exists(path) != MZ_OK)
    {
        // If the file doesn't exist, we don't append file
        mode |= MZ_OPEN_MODE_CREATE;
    }
    else if (append)
    {
        mode |= MZ_OPEN_MODE_APPEND;
    }
    else
    {
        if (writer->overwrite_cb != NULL)
            err_cb = writer->overwrite_cb(handle, writer->overwrite_cb, path);

        if (err_cb == MZ_INTERNAL_ERROR)
            return err;

        if (err_cb == MZ_OK)
            mode |= MZ_OPEN_MODE_CREATE;
        else
            mode |= MZ_OPEN_MODE_APPEND;
    }

    mz_stream_os_create(&writer->file_stream);
    mz_stream_buffered_create(&writer->buffered_stream);
    mz_stream_split_create(&writer->split_stream);

    mz_stream_set_base(writer->buffered_stream, writer->file_stream);
    mz_stream_set_base(writer->split_stream, writer->buffered_stream);

    mz_stream_split_set_prop_int64(writer->split_stream, MZ_STREAM_PROP_DISK_SIZE, disk_size);

    err = mz_stream_open(writer->split_stream, path, mode);
    if (err == MZ_OK)
        err = mz_zip_writer_open_int(handle, writer->split_stream, mode);

    return err;
}

int32_t mz_zip_writer_open_file_in_memory(void *handle, const char *path)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    void *file_stream = NULL;
    int64_t file_size = 0;
    int32_t err = 0;


    mz_zip_writer_close(handle);

    mz_stream_os_create(&file_stream);

    err = mz_stream_os_open(file_stream, path, MZ_OPEN_MODE_READ);

    if (err != MZ_OK)
    {
        mz_stream_os_delete(&file_stream);
        mz_zip_writer_close(handle);
        return err;
    }

    mz_stream_os_seek(file_stream, 0, SEEK_END);
    file_size = mz_stream_os_tell(file_stream);
    mz_stream_os_seek(file_stream, 0, SEEK_SET);

    if ((file_size <= 0) || (file_size > UINT32_MAX))
    {
        // Memory size is too large or too small

        mz_stream_os_close(file_stream);
        mz_stream_os_delete(&file_stream);
        mz_zip_writer_close(handle);
        return MZ_MEM_ERROR;
    }

    mz_stream_mem_create(&writer->mem_stream);
    mz_stream_mem_set_grow_size(writer->mem_stream, (int32_t)file_size);
    mz_stream_mem_open(writer->mem_stream, NULL, MZ_OPEN_MODE_CREATE);

    err = mz_stream_copy(writer->mem_stream, file_stream, (int32_t)file_size);

    mz_stream_os_close(file_stream);
    mz_stream_os_delete(&file_stream);

    if (err == MZ_OK)
        err = mz_zip_writer_open(handle, writer->mem_stream);
    if (err != MZ_OK)
        mz_zip_writer_close(handle);

    return err;
}

int32_t mz_zip_writer_close(void *handle)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t err = MZ_OK;

    if (writer->zip_handle != NULL)
    {
        mz_zip_set_version_madeby(writer->zip_handle, MZ_VERSION_MADEBY);
        err = mz_zip_close(writer->zip_handle);
        mz_zip_delete(&writer->zip_handle);
    }

    if (writer->split_stream != NULL)
    {
        mz_stream_split_close(writer->split_stream);
        mz_stream_split_delete(&writer->split_stream);
    }

    if (writer->buffered_stream != NULL)
        mz_stream_buffered_delete(&writer->buffered_stream);

    if (writer->file_stream != NULL)
        mz_stream_os_delete(&writer->file_stream);

    if (writer->mem_stream != NULL)
    {
        mz_stream_mem_close(writer->file_stream);
        mz_stream_mem_delete(&writer->file_stream);
    }

    return err;
}

/***************************************************************************/

int32_t mz_zip_writer_entry_open(void *handle, mz_zip_file *file_info)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t err = MZ_OK;
    const char *password = NULL;
    char password_buf[120];

    memcpy(&writer->file_info, file_info, sizeof(mz_zip_file));

    if (writer->entry_cb != NULL)
        writer->entry_cb(handle, writer->entry_userdata, &writer->file_info);

    password = writer->password;

    // Check if we need a password and ask for it if we need to
    if ((writer->file_info.flag & MZ_ZIP_FLAG_ENCRYPTED) && (password == NULL) &&
        (writer->password_cb != NULL))
    {
        writer->password_cb(handle, writer->password_userdata, &writer->file_info, password_buf, sizeof(password_buf));
        password = password_buf;
    }

    // Open entry in zip
    err = mz_zip_entry_write_open(writer->zip_handle, &writer->file_info, writer->compress_level, writer->raw, password);

    return err;
}

int32_t mz_zip_writer_entry_close(void *handle)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t err = MZ_OK;
    if (writer->raw)
        err = mz_zip_entry_close_raw(writer->zip_handle, writer->file_info.uncompressed_size, writer->file_info.crc);
    else
        err = mz_zip_entry_close(writer->zip_handle);
    return err;
}

int32_t mz_zip_writer_entry_write(void *handle, const void *buf, int32_t len)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t written = 0;
    written = mz_zip_entry_write(writer->zip_handle, buf, len);
    return written;
}

/***************************************************************************/

int32_t mz_zip_writer_add_process(void *handle, void *stream, mz_stream_read_cb read_cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t read = 0;
    int32_t written = 0;
    int32_t err = MZ_OK;

    if (mz_zip_writer_is_open(writer) != MZ_OK)
        return MZ_PARAM_ERROR;
    // If the entry isn't open for writing, open it
    if (mz_zip_entry_is_open(writer->zip_handle) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (read_cb == NULL)
        return MZ_PARAM_ERROR;

    read = read_cb(stream, writer->buffer, sizeof(writer->buffer));
    if (read == 0)
        return MZ_END_OF_STREAM;
    if (read < 0)
    {
        err = read;
        return err;
    }

    written = mz_zip_writer_entry_write(handle, writer->buffer, read);
    if (written != read)
        return MZ_STREAM_ERROR;

    return written;
}

int32_t mz_zip_writer_add(void *handle, void *stream, mz_stream_read_cb read_cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int64_t current_pos = 0;
    int64_t update_pos = 0;
    int32_t err = MZ_OK;
    int32_t written = 0;
    time_t current_time = time(NULL);
    time_t update_time = 0;


    // Update the progress at the beginning
    if (writer->progress_cb != NULL)
        writer->progress_cb(handle, writer->progress_userdata, &writer->file_info, current_pos);

    // Write data to stream until done
    while (err == MZ_OK)
    {
        written = mz_zip_writer_add_process(handle, stream, read_cb);
        if (written == MZ_END_OF_STREAM)
            break;
        if (written > 0)
            current_pos += written;
        if (written < 0)
            err = written;

        // Every 1 second lets update the progress 
        current_time = time(NULL);
        if ((current_time - update_time) > 1)
        {
            if (writer->progress_cb != NULL)
                writer->progress_cb(handle, writer->progress_userdata, &writer->file_info, current_pos);

            update_pos = current_pos;
            update_time = current_time;
        }
    }

    // Update the progress at the end
    if (writer->progress_cb != NULL && update_pos != current_pos)
        writer->progress_cb(handle, writer->progress_userdata, &writer->file_info, current_pos);

    return err;
}

int32_t mz_zip_writer_add_info(void *handle, void *stream, mz_stream_read_cb read_cb, mz_zip_file *file_info)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    int32_t err = MZ_OK;


    if (mz_zip_writer_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (file_info == NULL)
        return MZ_PARAM_ERROR;

    // Add to zip
    err = mz_zip_writer_entry_open(handle, file_info);
    if (err != MZ_OK)
        return err;

    if (stream != NULL)
    {
        if (mz_zip_attrib_is_dir(writer->file_info.external_fa, writer->file_info.version_madeby) != MZ_OK)
            err = mz_zip_writer_add(handle, stream, read_cb);
    }

    err = mz_zip_writer_entry_close(handle);

    return err;
}

int32_t mz_zip_writer_add_buffer(void *handle, void *buf, int32_t len, mz_zip_file *file_info)
{
    void *mem_stream = NULL;
    int32_t err = MZ_OK;

    if (mz_zip_writer_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (buf == NULL)
        return MZ_PARAM_ERROR;

    // Create a memory stream backed by our buffer and add from it
    mz_stream_mem_create(&mem_stream);
    mz_stream_mem_set_buffer(mem_stream, buf, len);

    err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_READ);
    if (err == MZ_OK)
        err = mz_zip_writer_add_info(handle, mem_stream, mz_stream_mem_read, file_info);

    mz_stream_mem_delete(&mem_stream);
    return err;
}

int32_t mz_zip_writer_add_file(void *handle, const char *path, const char *filename_in_zip)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    mz_zip_file file_info;
    int32_t err = MZ_OK;
    void *stream = NULL;
    const char *filename = filename_in_zip;


    if (mz_zip_writer_is_open(handle) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (path == NULL)
        return MZ_PARAM_ERROR;

    if (filename == NULL)
    {
        err = mz_path_get_filename(path, &filename);
        if (err != MZ_OK)
            return err;
    }

    memset(&file_info, 0, sizeof(file_info));

    // The path name saved, should not include a leading slash.
    // If it did, windows/xp and dynazip couldn't read the zip file.

    while (filename[0] == '\\' || filename[0] == '/')
        filename += 1;

    // Get information about the file on disk so we can store it in zip
    
    file_info.version_madeby = MZ_VERSION_MADEBY;
    file_info.compression_method = writer->compress_method;
    file_info.filename = filename;
    file_info.filename_size = (uint16_t)strlen(filename);
    file_info.uncompressed_size = mz_os_get_file_size(path);

#ifdef HAVE_AES
    if (writer->aes)
        file_info.aes_version = MZ_AES_VERSION;
#endif

    mz_os_get_file_date(path, &file_info.modified_date, &file_info.accessed_date,
        &file_info.creation_date);
    mz_os_get_file_attribs(path, &file_info.external_fa);

    if (mz_os_is_dir(path) != MZ_OK)
    {
        mz_stream_os_create(&stream);
        err = mz_stream_os_open(stream, path, MZ_OPEN_MODE_READ);
    }

    if (err == MZ_OK)
        err = mz_zip_writer_add_info(handle, stream, mz_stream_os_read, &file_info);

    if (stream != NULL)
    {
        mz_stream_os_close(stream);
        mz_stream_os_delete(&stream);
    }

    return err;
}

int32_t mz_zip_writer_add_path(void *handle, const char *path, const char *root_path, uint8_t include_path, uint8_t recursive)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    int32_t err = MZ_OK;
    int16_t is_dir = 0;
    const char *filename = NULL;
    const char *filenameinzip = path;
    char *wildcard_ptr = NULL;
    char full_path[320];
    char path_dir[320];


    if (mz_os_is_dir(path) == MZ_OK)
        is_dir = 1;

    if (strrchr(path, '*') != NULL)
    {
        strncpy(path_dir, path, sizeof(path_dir));
        mz_path_remove_filename(path_dir);
        wildcard_ptr = path_dir + strlen(path_dir) + 1;
        root_path = path = path_dir;
    }
    else
    {
        // Construct the filename that our file will be stored in the zip as
        if (root_path == NULL)
            root_path = path;

        // Should the file be stored with any path info at all?
        if (!include_path)
        {
            if (!is_dir && root_path == path)
            {
                if (mz_path_get_filename(filenameinzip, &filename) == MZ_OK)
                    filenameinzip = filename;
            }
            else
            {
                filenameinzip += strlen(root_path);
            }
        }

        if (*filenameinzip != 0)
            err = mz_zip_writer_add_file(handle, path, filenameinzip);

        if (!is_dir)
            return err;
    }

    dir = mz_os_open_dir(path);

    if (dir == NULL)
        return MZ_EXIST_ERROR;

    while ((entry = mz_os_read_dir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        full_path[0] = 0;
        mz_path_combine(full_path, path, sizeof(full_path));
        mz_path_combine(full_path, entry->d_name, sizeof(full_path));

        if (!recursive && mz_os_is_dir(full_path))
            continue;
        if ((wildcard_ptr != NULL) && (mz_path_compare_wc(entry->d_name, wildcard_ptr, 1) != MZ_OK))
            continue;

        err = mz_zip_writer_add_path(handle, full_path, root_path, include_path, recursive);
        if (err != MZ_OK)
            return err;
    }

    mz_os_close_dir(dir);
    return MZ_OK;
}

int32_t mz_zip_writer_copy_from_reader(void *handle, void *reader)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    mz_zip_file *file_info = NULL;
    int32_t err = MZ_OK;
    uint8_t original_raw = 0;
    void *reader_zip_handle = NULL;


    if (mz_zip_reader_is_open(reader) != MZ_OK)
        return MZ_PARAM_ERROR;
    if (mz_zip_writer_is_open(writer) != MZ_OK)
        return MZ_PARAM_ERROR;

    err = mz_zip_reader_entry_get_info(reader, &file_info);
    if (err != MZ_OK)
        return err;

    mz_zip_reader_get_zip_handle(reader, &reader_zip_handle);

    // Open entry for raw reading
    err = mz_zip_entry_read_open(reader_zip_handle, 1, NULL);
    if (err == MZ_OK)
    {
        // Write entry raw, save original raw value
        original_raw = writer->raw;
        writer->raw = 1;

        err = mz_zip_writer_add_info(writer, reader_zip_handle, mz_zip_entry_read, file_info);

        writer->raw = original_raw;

        mz_zip_entry_close(reader_zip_handle);
    }

    return err;
}

/***************************************************************************/

void mz_zip_writer_set_password(void *handle, const char *password)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->password = password;
}

void mz_zip_writer_set_raw(void *handle, uint8_t raw)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->raw = raw;
}

int32_t mz_zip_writer_get_raw(void *handle, uint8_t *raw)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    if (raw == NULL)
        return MZ_PARAM_ERROR;
    *raw = writer->raw;
    return MZ_OK;
}

void mz_zip_writer_set_aes(void *handle, uint8_t aes)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->aes = aes;
}

void mz_zip_writer_set_compress_method(void *handle, int16_t compress_method)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->compress_method = compress_method;
}

void mz_zip_writer_set_compress_level(void *handle, int16_t compress_level)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->compress_level = compress_level;
}

void mz_zip_writer_set_overwrite_cb(void *handle, void *userdata, mz_zip_writer_overwrite_cb cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->overwrite_cb = cb;
    writer->overwrite_userdata = userdata;
}

void mz_zip_writer_set_password_cb(void *handle, void *userdata, mz_zip_writer_password_cb cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->password_cb = cb;
    writer->password_userdata = userdata;
}

void mz_zip_writer_set_progress_cb(void *handle, void *userdata, mz_zip_writer_progress_cb cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->progress_cb = cb;
    writer->progress_userdata = userdata;
}

void mz_zip_writer_set_entry_cb(void *handle, void *userdata, mz_zip_writer_entry_cb cb)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    writer->entry_cb = cb;
    writer->entry_userdata = userdata;
}

int32_t mz_zip_writer_get_zip_handle(void *handle, void **zip_handle)
{
    mz_zip_writer *writer = (mz_zip_writer *)handle;
    if (zip_handle == NULL)
        return MZ_PARAM_ERROR;
    *zip_handle = writer->zip_handle;
    if (*zip_handle == NULL)
        return MZ_EXIST_ERROR;
    return MZ_OK;
}

/***************************************************************************/

void *mz_zip_writer_create(void **handle)
{
    mz_zip_writer *writer = NULL;

    writer = (mz_zip_writer *)MZ_ALLOC(sizeof(mz_zip_writer));
    if (writer != NULL)
    {
        memset(writer, 0, sizeof(mz_zip_writer));

        writer->compress_method = MZ_COMPRESS_METHOD_DEFLATE;
        writer->compress_level = MZ_COMPRESS_LEVEL_BEST;
    }
    if (writer != NULL)
        *handle = writer;

    return writer;
}

void mz_zip_writer_delete(void **handle)
{
    mz_zip_writer *writer = NULL;
    if (handle == NULL)
        return;
    writer = (mz_zip_writer *)*handle;
    if (writer != NULL)
    {
        mz_zip_writer_close(writer);
        MZ_FREE(writer);
    }
    *handle = NULL;
}

/***************************************************************************/
