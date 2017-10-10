/* mz_strm_split.c -- Stream for split files
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This file is under the same license as the Unzip tool it is distributed
   with.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mz_error.h"
#include "mz_strm.h"
#include "mz_strm_split.h"

/***************************************************************************/

mz_stream_vtbl mz_stream_split_vtbl = {
    mz_stream_split_open,
    mz_stream_split_is_open,
    mz_stream_split_read,
    mz_stream_split_write,
    mz_stream_split_tell,
    mz_stream_split_seek,
    mz_stream_split_close,
    mz_stream_split_error,
    mz_stream_split_create,
    mz_stream_split_delete,
    mz_stream_split_get_prop_int64,
    mz_stream_split_set_prop_int64
};

/***************************************************************************/

typedef struct mz_stream_split_s {
    mz_stream   stream;
    int64_t     disk_size;
    int16_t     disk_directory;
    int64_t     total_out;
    int64_t     total_out_disk;
    int32_t     mode;
    char        *path;
    int32_t     path_size;
    char        *current_path;
    int32_t     current_path_size;
    int32_t     number_disk;
    int32_t     reached_end;
} mz_stream_split;

/***************************************************************************/

#define DISKHEADERMAGIC             (0x08074b50)

/***************************************************************************/

int32_t mz_stream_split_open_disk(void *stream, int32_t number_disk)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    int32_t i = 0;
    int16_t err = MZ_OK;


    if (split->disk_directory == 0)
    {
        for (i = strlen(split->current_path) - 1; i >= 0; i -= 1)
        {
            if (split->current_path[i] != '.')
                continue;
            _snprintf(&split->current_path[i], split->current_path_size - i, ".z%02d", number_disk + 1);
            break;
        }
    }
    else
    {
        strncpy(split->current_path, split->path, split->current_path_size);
    }
    
    err = mz_stream_open(split->stream.base, split->current_path, split->mode);

    if (err == MZ_OK)
    {
        split->total_out_disk = 0;
        if (split->total_out == 0)
        {
            err = mz_stream_write_uint32(split->stream.base, DISKHEADERMAGIC);
            split->total_out_disk += 4;
        }
        split->total_out += split->total_out_disk;
    }
    
    return err;
}

int32_t mz_stream_split_close_disk(void *stream)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    return mz_stream_close(split->stream.base);
}

int32_t mz_stream_split_open(void *stream, const char *path, int32_t mode)
{
    mz_stream_split *split = (mz_stream_split *)stream;

    split->mode = mode;

    split->path_size = strlen(path) + 1;
    split->path = (char *)malloc(split->path_size);
    strncpy(split->path, path, split->path_size);

    split->current_path_size = strlen(path) + 10;
    split->current_path = (char *)malloc(split->current_path_size);
    strncpy(split->current_path, path, split->current_path_size);

    return mz_stream_split_open_disk(stream, split->number_disk);
}

int32_t mz_stream_split_is_open(void *stream)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    return mz_stream_is_open(split->stream.base);
}

int32_t mz_stream_split_read(void *stream, void *buf, int32_t size)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    return size;
}

int32_t mz_stream_split_write(void *stream, const void *buf, int32_t size)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    int32_t written = 0;
    int32_t bytes_left = size;
    int32_t bytes_to_write = size;
    int32_t bytes_avail = 0;
    int16_t err = MZ_OK;
    uint8_t *buf_ptr = (uint8_t *)buf;

    
    while ((err == MZ_OK) && (bytes_left > 0))
    {
        if ((split->total_out_disk == split->disk_size && split->total_out > 0) || 
            (split->disk_directory == 1))
        {
            err = mz_stream_split_close_disk(stream);
            if (err == MZ_OK)
            {
                split->number_disk += 1;
                err = mz_stream_split_open_disk(stream, split->number_disk);
            }

            if (split->disk_directory > 0)
                split->disk_directory += 1;
        }

        if (err == MZ_OK)
        {
            bytes_avail = (int32_t)(split->disk_size - split->total_out_disk);
            bytes_to_write = bytes_left;
            if (bytes_to_write > bytes_avail)
                bytes_to_write = bytes_avail;

            written = mz_stream_write(split->stream.base, buf_ptr, bytes_to_write);
            if (written != bytes_to_write)
                return MZ_STREAM_ERROR;

            bytes_left -= written;
            buf_ptr += written;
            split->total_out += written;
            split->total_out_disk += written;
        }
    }

    return size - bytes_left;
}

int64_t mz_stream_split_tell(void *stream)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    return mz_stream_tell(split->stream.base);
}

int32_t mz_stream_split_seek(void *stream, int64_t offset, int32_t origin)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    return MZ_OK;
}

int32_t mz_stream_split_close(void *stream)
{
    return MZ_OK;
}

int32_t mz_stream_split_error(void *stream)
{
    return MZ_OK;
}

int32_t mz_stream_split_get_prop_int64(void *stream, int32_t prop, int64_t *value)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = split->total_out;
        return MZ_OK;
    case MZ_STREAM_PROP_DISK_NUMBER:
        *value = split->number_disk;
        return MZ_OK;
    case MZ_STREAM_PROP_DISK_SIZE:
        *value = split->disk_size;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

int32_t mz_stream_split_set_prop_int64(void *stream, int32_t prop, int64_t value)
{
    mz_stream_split *split = (mz_stream_split *)stream;
    switch (prop)
    {
    case MZ_STREAM_PROP_DISK_SIZE:
        split->disk_size = value;
        return MZ_OK;
    case MZ_STREAM_PROP_DISK_DIRECTORY:
        split->disk_directory = (int16_t)value;
        return MZ_OK;
    }
    return MZ_EXIST_ERROR;
}

void *mz_stream_split_create(void **stream)
{
    mz_stream_split *split = NULL;

    split = (mz_stream_split *)malloc(sizeof(mz_stream_split));
    if (split != NULL)
    {
        memset(split, 0, sizeof(mz_stream_split));
        split->stream.vtbl = &mz_stream_split_vtbl;
        split->disk_size = 64 * 1024;
    }
    if (stream != NULL)
        *stream = split;

    return split;
}

void mz_stream_split_delete(void **stream)
{
    mz_stream_split *split = NULL;
    if (stream == NULL)
        return;
    split = (mz_stream_split *)*stream;
    if (split != NULL)
    {
        free(split);
    }
    *stream = NULL;
}

void *mz_stream_split_get_interface(void)
{
    return (void *)&mz_stream_split_vtbl;
}