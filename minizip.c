/* minizip.c
   Version 2.0.0, October 4th, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 2007-2008 Even Rouault
     Modifications of Unzip for Zip64
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include "mz_zip.h"
#include "mz_strm.h"

/***************************************************************************/

void minizip_banner()
{
    printf("Minizip 2.0.0 - https://github.com/nmoinvaz/minizip\n");
    printf("---------------------------------------------------\n");
}

void minizip_help()
{
    printf("Usage : minizip [-o] [-a] [-0 to -9] [-p password] [-j] file.zip [files_to_add]\n\n" \
           "  -o  Overwrite existing file.zip\n" \
           "  -a  Append to existing file.zip\n" \
           "  -0  Store only\n" \
           "  -1  Compress faster\n" \
           "  -9  Compress better\n" \
           "  -b  BZIP2 compression\n" \
           "  -m  LZMA compression\n" \
           "  -s  AES encryption\n" \
           "  -j  Exclude path and store only the file name\n\n");
}

/***************************************************************************/

int32_t minizip_addfile(void *handle, const char *path, const char *filenameinzip, mz_zip_compress *compress_info, mz_zip_crypt *crypt_info)
{
    mz_zip_file file_info = { 0 };
    int32_t read = 0;
    int16_t err = MZ_OK;
    int16_t err_close = MZ_OK;
    void *stream = NULL;
    char buf[UINT16_MAX];


    // Get information about the file on disk so we can store it in zip
    printf("Adding: %s\n", filenameinzip);

    file_info.filename = filenameinzip;

    if (mz_os_file_get_size(path) >= UINT32_MAX)
        file_info.zip64 = 1;

    mz_os_get_file_date(path, &file_info.dos_date);

    // Add to zip
    err = mz_zip_entry_open(handle, &file_info, compress_info, crypt_info);
    if (err != MZ_OK)
    {
        printf("Error in opening %s in zip file (%d)\n", filenameinzip, err);
        return err;
    }

    mz_stream_os_create(&stream);

    err = mz_stream_os_open(stream, path, MZ_STREAM_MODE_READ);

    if (err == MZ_OK)
    {
        // Read contents of file and write it to zip
        do
        {
            read = mz_stream_os_read(stream, buf, sizeof(buf));
            if (read < 0)
            {
                err = mz_stream_os_error(stream);
                printf("Error %d in reading %s\n", err, filenameinzip);
                break;
            }
            if (read == 0)
                break;

            err = mz_zip_entry_write(handle, buf, read);
            if (err < 0)
                printf("Error in writing %s in the zip file (%d)\n", filenameinzip, err);
        }
        while (err == MZ_OK);

        mz_stream_os_close(stream);
    }
    else
    {
        printf("Error in opening %s for reading\n", path);
    }

    mz_stream_os_delete(&stream);

    err_close = mz_zip_entry_close(handle);
    if (err_close != MZ_OK)
        printf("Error in closing %s in the zip file (%d)\n", filenameinzip, err_close);

    return err;
}

#ifndef NOMAIN
int main(int argc, char *argv[])
{
    void *handle = NULL;
    void *stream = NULL;
    char *path = NULL;
    mz_zip_compress compress_info;
    mz_zip_crypt crypt_info;
    int32_t path_arg = 0;
    uint8_t opt_append = 0;
    uint8_t opt_open_existing = 0;
    uint8_t opt_exclude_path = 0;
    int16_t mode = 0;
    int16_t err_close = 0;
    int16_t err = 0;
    int16_t i = 0;

    minizip_banner();
    if (argc == 1)
    {
        minizip_help();
        return 0;
    }

    memset(&compress_info, 0, sizeof(compress_info));
    memset(&crypt_info, 0, sizeof(crypt_info));

    compress_info.method = MZ_METHOD_DEFLATE;
    compress_info.level = MZ_COMPRESS_LEVEL_DEFAULT;

    // Parse command line options
    for (i = 1; i < argc; i++)
    {
        if ((*argv[i]) == '-')
        {
            const char *p = argv[i]+1;

            while ((*p) != '\0')
            {
                char c = *(p++);
                if ((c == 'o') || (c == 'O'))
                    opt_append = 1;
                if ((c == 'a') || (c == 'A'))
                    opt_open_existing = 1;
                if ((c >= '0') && (c <= '9'))
                {
                    compress_info.level = (c - '0');
                    if (compress_info.level == 0)
                        compress_info.method = MZ_METHOD_RAW;
                }
                if ((c == 'j') || (c == 'J'))
                    opt_exclude_path = 1;
                if ((c == 'b') || (c == 'B'))
                    compress_info.method = MZ_METHOD_BZIP2;
                if ((c == 'm') || (c == 'M'))
                    compress_info.method = MZ_METHOD_LZMA;
                if ((c == 's') || (c == 'S'))
                    crypt_info.aes = 1;

                if (((c == 'p') || (c == 'P')) && (i + 1 < argc))
                {
                    crypt_info.password = argv[i + 1];
                    i += 1;
                }
            }

            continue;
        }

        if (path_arg == 0)
            path_arg = i;
    }

    if (path_arg == 0)
    {
        minizip_help();
        return 0;
    }

    path = argv[path_arg];

    if (opt_open_existing)
    {
        // If the file don't exist, we not append file
        if (mz_os_file_exists(path) != MZ_OK)
            opt_append = 0;
    }
    else if (opt_append == 0)
    {
        // If ask the user what to do because append and overwrite args not set
        if (mz_os_file_exists(path) != 0)
        {
            char rep = 0;
            do
            {
                char answer[128];
                printf("The file %s exists. Overwrite ? [y]es, [n]o, [a]ppend : ", path);
                if (scanf("%1s", answer) != 1)
                    exit(EXIT_FAILURE);
                rep = answer[0];

                if ((rep >= 'a') && (rep <= 'z'))
                    rep -= 0x20;
            }
            while ((rep != 'Y') && (rep != 'N') && (rep != 'A'));

            if (rep == 'A')
            {
                opt_open_existing = 1;
            }
            else if (rep == 'N')
            {
                minizip_help();
                return 0;
            }
        }
    }

    mz_stream_os_create(&stream);

    mode = MZ_STREAM_MODE_READWRITE;
    if (opt_append)
        mode |= MZ_STREAM_MODE_APPEND;
    else
        mode |= MZ_STREAM_MODE_CREATE;

    if (mz_stream_open(stream, path, mode) != MZ_OK)
    {
        mz_stream_os_delete(&stream);
        printf("Error opening file %s\n", path);
        return 1;
    }
    
    handle = mz_zip_open(opt_open_existing, 0, stream);

    if (handle == NULL)
    {
        mz_stream_os_delete(&stream);
        printf("Error opening zip %s\n", path);
        return 1;
    }

    printf("Creating %s\n", path);

    // Go through command line args looking for files to add to zip
    for (i = path_arg + 1; (i < argc) && (err == MZ_OK); i++)
    {
        const char *filename = argv[i];
        const char *filenameinzip = NULL;


        // Skip command line options
        if ((((*(argv[i])) == '-') || ((*(argv[i])) == '/')) && (strlen(argv[i]) == 2) &&
            ((argv[i][1] == 'o') || (argv[i][1] == 'O') || (argv[i][1] == 'a') || (argv[i][1] == 'A') ||
             (argv[i][1] == 'p') || (argv[i][1] == 'P') || ((argv[i][1] >= '0') && (argv[i][1] <= '9'))))
            continue;

        // Construct the filename that our file will be stored in the zip as.
        // The path name saved, should not include a leading slash.
        // If it did, windows/xp and dynazip couldn't read the zip file. 

        filenameinzip = filename;
        while (filenameinzip[0] == '\\' || filenameinzip[0] == '/')
            filenameinzip += 1;

        // Should the file be stored with any path info at all?
        if (opt_exclude_path)
        {
            const char *match = NULL;
            const char *last_slash = NULL;

            for (match = filenameinzip; *match; match += 1)
            {
                if (*match == '\\' || *match == '/')
                    last_slash = match;
            }

            if (last_slash != NULL)
                filenameinzip = last_slash + 1; // base filename follows last slash
        }

        err = minizip_addfile(handle, filename, filenameinzip, &compress_info, &crypt_info);
    }

    err_close = mz_zip_close(handle, NULL, 0);
    if (err_close != MZ_OK)
        printf("Error in closing %s (%d)\n", path, err_close);

    mz_stream_os_close(stream);
    mz_stream_os_delete(&stream);

    return err;
}
#endif
