/* iowin32.c -- IO base function header for compress/uncompress .zip
   Version 1.2.0, September 16th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <tchar.h>

#include "zlib.h"
#include "ioapi.h"
#include "iowin32.h"

#ifndef INVALID_HANDLE_VALUE
#  define INVALID_HANDLE_VALUE (0xFFFFFFFF)
#endif

#ifndef INVALID_SET_FILE_POINTER
#  define INVALID_SET_FILE_POINTER ((DWORD)-1)
#endif

#if defined(WINAPI_FAMILY_PARTITION) && (!(defined(IOWIN32_USING_WINRT_API)))
#  if !WINAPI_FAMILY_PARTITION(WINAPI_PARTITION_DESKTOP)
#    define IOWIN32_USING_WINRT_API 1
#  endif
#endif

typedef struct mzstream_win32_s
{
    mzstream   stream;
    HANDLE      handle;
    int         error;
    char        *filename;
    int         filename_size;
} mzstream_win32;

int32_t ZCALLBACK mzstream_win32_open(voidpf stream, const char *filename, int mode)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    uint32_t desired_access = 0;
    uint32_t creation_disposition = 0;
    uint32_t share_mode = 0;
    uint32_t flags_attribs = FILE_ATTRIBUTE_NORMAL;
    wchar_t *filename_wide = NULL;
    uint32_t filename_wide_size = 0;
    HANDLE handle = NULL;

    if (filename == NULL)
        return MZSTREAM_ERR;

    if ((mode & MZSTREAM_MODE_READWRITEFILTER) == MZSTREAM_MODE_READ)
    {
        desired_access = GENERIC_READ;
        creation_disposition = OPEN_EXISTING;
        share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;
    }
    else if (mode & MZSTREAM_MODE_EXISTING)
    {
        desired_access = GENERIC_WRITE | GENERIC_READ;
        creation_disposition = OPEN_EXISTING;
    }
    else if (mode & MZSTREAM_MODE_CREATE)
    {
        desired_access = GENERIC_WRITE | GENERIC_READ;
        creation_disposition = CREATE_ALWAYS;
    }
    else
    {
        return MZSTREAM_ERR;
    }

    filename_wide_size = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    filename_wide = (wchar_t *)malloc((filename_wide_size + 1) * sizeof(wchar_t));
    memset(filename_wide, 0, sizeof(wchar_t) * (filename_wide_size + 1));

    MultiByteToWideChar(CP_UTF8, 0, filename, -1, filename_wide, filename_wide_size);

#ifdef IOWIN32_USING_WINRT_API
    win32->handle = CreateFile2W(filename_wide, desired_access, share_mode, creation_disposition, NULL);
#else
    win32->handle = CreateFileW(filename_wide, desired_access, share_mode, NULL, creation_disposition, flags_attribs, NULL);
#endif

    free(filename_wide);

    if (mzstream_win32_is_open(stream) == MZSTREAM_ERR)
        return MZSTREAM_ERR;

    win32->filename_size = strlen(filename) + 1;
    win32->filename = (char *)malloc(win32->filename_size);

    strncpy(win32->filename, filename, win32->filename_size);

    return MZSTREAM_OK; 
}

int32_t ZCALLBACK mzstream_win32_is_open(voidpf stream)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    if (win32->handle == NULL || win32->handle == INVALID_HANDLE_VALUE)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_win32_read(voidpf stream, void* buf, uint32_t size)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    uint32_t read = 0;
    HANDLE handle = NULL;

    if (mzstream_win32_is_open(stream) == MZSTREAM_ERR)
        return MZSTREAM_ERR;

    if (!ReadFile(win32->handle, buf, size, &read, NULL))
    {
        win32->error = GetLastError();
        if (win32->error == ERROR_HANDLE_EOF)
            win32->error = 0;
    }

    return read;
}

int32_t ZCALLBACK mzstream_win32_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    uint32_t written = 0;
    uint32_t error = 0;
    HANDLE handle = NULL;

    if (mzstream_win32_is_open(stream) == MZSTREAM_ERR)
        return MZSTREAM_ERR;

    if (!WriteFile(win32->handle, buf, size, &written, NULL))
    {
        win32->error = GetLastError();
        if (win32->error == ERROR_HANDLE_EOF)
            win32->error = 0;
    }

    return written;
}

static int32_t mzstream_win32_seekinternal(HANDLE handle, LARGE_INTEGER large_pos, LARGE_INTEGER *new_pos, uint32_t move_method)
{
#ifdef IOWIN32_USING_WINRT_API
    return SetFilePointerEx(handle, pos, newPos, dwMoveMethod);
#else
    LONG high_part = large_pos.HighPart;
    uint32_t pos = SetFilePointer(handle, large_pos.LowPart, &high_part, move_method);

    if ((pos == INVALID_SET_FILE_POINTER) && (GetLastError() != NO_ERROR))
        return MZSTREAM_ERR;

    if (new_pos != NULL)
    {
        new_pos->LowPart = pos;
        new_pos->HighPart = high_part;
    }

    return MZSTREAM_OK;
#endif
}

int64_t ZCALLBACK mzstream_win32_tell(voidpf stream)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    uint32_t written = 0;
    uint32_t error = 0;
    HANDLE handle = NULL;
    LARGE_INTEGER large_pos;

    if (mzstream_win32_is_open(stream) == MZSTREAM_ERR)
        return MZSTREAM_ERR;

    large_pos.QuadPart = 0;

    if (mzstream_win32_seekinternal(win32->handle, large_pos, &large_pos, FILE_CURRENT) == MZSTREAM_ERR)
    {
        error = GetLastError();
        win32->error = error;
    }

    return large_pos.LowPart;
}

int32_t ZCALLBACK mzstream_win32_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    uint32_t move_method = 0xFFFFFFFF;
    uint32_t error = 0;
    HANDLE handle = NULL;
    int64_t position = -1;
    LARGE_INTEGER large_pos;


    if (mzstream_win32_is_open(stream) == MZSTREAM_ERR)
        return MZSTREAM_ERR;

    switch (origin)
    {
        case MZSTREAM_SEEK_CUR:
            move_method = FILE_CURRENT;
            break;
        case MZSTREAM_SEEK_END:
            move_method = FILE_END;
            break;
        case MZSTREAM_SEEK_SET:
            move_method = FILE_BEGIN;
            break;
        default:
            return MZSTREAM_ERR;
    }

    large_pos.QuadPart = offset;

    if (mzstream_win32_seekinternal(win32->handle, large_pos, NULL, move_method) == MZSTREAM_ERR)
    {
        error = GetLastError();
        win32->error = error;
        return MZSTREAM_ERR;
    }

    return MZSTREAM_OK;
}

int ZCALLBACK mzstream_win32_close(voidpf stream)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;

    if (win32->filename != NULL)
        free(win32->filename);
    if (win32->handle != NULL)
        CloseHandle(win32->handle);
    win32->handle = NULL;
    return MZSTREAM_OK;
}

int ZCALLBACK mzstream_win32_error(voidpf stream)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    return win32->error;
}

voidpf mzstream_win32_alloc(void)
{
    mzstream_win32 *win32 = NULL;

    win32 = (mzstream_win32 *)malloc(sizeof(mzstream_win32));
    if (win32 == NULL)
        return NULL;

    memset(win32, 0, sizeof(mzstream_win32));

    win32->stream.open = mzstream_win32_open;
    win32->stream.is_open = mzstream_win32_is_open;
    win32->stream.read = mzstream_win32_read;
    win32->stream.write = mzstream_win32_write;
    win32->stream.tell = mzstream_win32_tell;
    win32->stream.seek = mzstream_win32_seek;
    win32->stream.close = mzstream_win32_close;
    win32->stream.error = mzstream_win32_error;
    win32->stream.alloc = mzstream_win32_alloc;
    win32->stream.free = mzstream_win32_free;

    return (voidpf)win32;
}

void mzstream_win32_free(voidpf stream)
{
    mzstream_win32 *win32 = (mzstream_win32 *)stream;
    if (win32 != NULL)
        free(win32);
}