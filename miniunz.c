/* miniunz.c
   Version 1.3.0, September 16th, 2017
   sample part of the MiniZip project

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

#include "mz_strm.h"
#include "mz_unzip.h"

/***************************************************************************/

void miniunz_banner()
{
    printf("MiniUnz 1.3.0, demo of zLib + Unz package\n");
    printf("more info at https://github.com/nmoinvaz/minizip\n\n");
}

void miniunz_help()
{
    printf("Usage : miniunz [-e] [-x] [-v] [-l] [-o] [-p password] file.zip [file_to_extr.] [-d extractdir]\n\n" \
           "  -e  Extract without path (junk paths)\n" \
           "  -x  Extract with path\n" \
           "  -v  list files\n" \
           "  -l  list files\n" \
           "  -d  directory to extract into\n" \
           "  -o  overwrite files without prompting\n" \
           "  -p  extract crypted file using password\n\n");
}

/***************************************************************************/

int32_t miniunz_list(void *handle)
{
    mz_unzip_file *file_info = NULL;
    uint32_t ratio = 0;
    int16_t level = 0;
    int16_t err = MZ_OK;
    struct tm tmu_date = { 0 };
    const char *string_method = NULL;
    char crypt = ' ';


    err = mz_unzip_goto_first_entry(handle);

    if (err != MZ_OK)
    {
        printf("Error %d going to first entry in zip file\n", err);
        return err;
    }

    printf("  Length  Method     Size Ratio   Date    Time   CRC-32     Name\n");
    printf("  ------  ------     ---- -----   ----    ----   ------     ----\n");

    do
    {
        err = mz_unzip_entry_get_info(handle, &file_info);
        if (err != MZ_OK)
        {
            printf("Error %d getting entry info in zip file\n", err);
            break;
        }

        if (file_info->uncompressed_size > 0)
            ratio = (uint32_t)((file_info->compressed_size * 100) / file_info->uncompressed_size);

        // Display a '*' if the file is encrypted
        if ((file_info->flag & 1) != 0)
            crypt = '*';

        if (file_info->compression_method == 0)
        {
            string_method = "Stored";
        }
        else if (file_info->compression_method == MZ_METHOD_DEFLATE)
        {
            level = (int16_t)((file_info->flag & 0x6) / 2);
            if (level == 0)
                string_method = "Defl:N";
            else if (level == 1)
                string_method = "Defl:X";
            else if ((level == 2) || (level == 3))
                string_method = "Defl:F"; // 2:fast , 3 : extra fast
            else
                string_method = "Unkn. ";
        }
        else if (file_info->compression_method == MZ_METHOD_BZIP2)
        {
            string_method = "BZip2 ";
        }
        else if (file_info->compression_method == MZ_METHOD_LZMA)
        {
            string_method = "LZMA ";
        }
        else
        {
            string_method = "Unkn. ";
        }

        mz_dosdate_to_tm(file_info->dos_date, &tmu_date);

        printf(" %7llu  %6s%c %7llu %3u%%  %2.2u-%2.2u-%2.2u  %2.2u:%2.2u  %8.8x   %s\n", 
            file_info->uncompressed_size, string_method, crypt, file_info->compressed_size, ratio, 
            (uint32_t)tmu_date.tm_mon + 1, (uint32_t)tmu_date.tm_mday,
            (uint32_t)tmu_date.tm_year % 100,
            (uint32_t)tmu_date.tm_hour, (uint32_t)tmu_date.tm_min,
            file_info->crc, file_info->filename);

        err = mz_unzip_goto_next_entry(handle);
    }
    while (err == MZ_OK);

    if (err != MZ_END_OF_LIST && err != MZ_OK)
    {
        printf("Error %d going to next entry in zip file\n", err);
        return err;
    }

    return MZ_OK;
}

int32_t miniunz_extract_currentfile(void *handle, uint8_t opt_extract_without_path, uint8_t *opt_overwrite, const char *password)
{
    mz_unzip_file *file_info = NULL;
    uint8_t buf[UINT16_MAX];
    int32_t read = 0;
    int32_t written = 0;
    int16_t err = MZ_OK;
    int16_t err_close = MZ_OK;
    uint8_t skip = 0;
    void *stream = NULL;
    char *match = NULL;
    char *filename = NULL;
    char *write_filename = NULL;
    char directory[512];


    err = mz_unzip_entry_get_info(handle, &file_info);

    if (err != MZ_OK)
    {
        printf("Error %d getting entry info in zip file\n", err);
        return err;
    }

    // Break apart filename and directory from full path
    strncpy(directory, file_info->filename, sizeof(directory));
    match = filename = directory;
    while (*match != 0)
    {
        if ((*match == '/') || (*match == '\\'))
            filename = match + 1;
        match += 1;
    }
    if (filename != directory)
        *match = 0;

    // If zip entry is a directory then create it on disk
    if (*filename == 0)
    {
        if (opt_extract_without_path == 0)
        {
            printf("Creating directory: %s\n", file_info->filename);
            mz_os_make_dir(directory);
        }

        return err;
    }

    err = mz_unzip_entry_open(handle, 0, password);

    if (err != MZ_OK)
    {
        printf("Error %d opening entry in zip file\n", err);
        return err;
    }

    if (opt_extract_without_path)
        write_filename = filename;
    else
        write_filename = file_info->filename;

    // Determine if the file should be overwritten or not and ask the user if needed
    if ((err == MZ_OK) && (*opt_overwrite == 0) && (mz_os_file_exists(write_filename)))
    {
        char rep = 0;
        do
        {
            char answer[128];
            printf("The file %s exists. Overwrite ? [y]es, [n]o, [A]ll: ", write_filename);
            if (scanf("%1s", answer) != 1)
                exit(EXIT_FAILURE);
            rep = answer[0];
            if ((rep >= 'a') && (rep <= 'z'))
                rep -= 0x20;
        }
        while ((rep != 'Y') && (rep != 'N') && (rep != 'A'));

        if (rep == 'N')
            skip = 1;
        if (rep == 'A')
            *opt_overwrite = 1;
    }

    mz_stream_os_create(&stream);

    // Create the file on disk so we can unzip to it
    if ((skip == 0) && (err == MZ_OK))
    {
        // Some zips don't contain directory alone before file
        if ((mz_stream_os_open(stream, write_filename, MZ_STREAM_MODE_CREATE) != MZ_OK) &&
            (opt_extract_without_path == 0) && (filename != file_info->filename))
        {
            mz_os_make_dir(directory);
            mz_stream_os_open(stream, write_filename, MZ_STREAM_MODE_CREATE);
        }
    }

    // Read from the zip, unzip to buffer, and write to disk
    if (mz_stream_os_is_open(stream) == MZ_OK)
    {
        printf(" Extracting: %s\n", write_filename);
        while (1)
        {
            read = mz_unzip_entry_read(handle, buf, sizeof(buf));
            if (read < 0)
            {
                err = read;
                printf("Error %d  reading entry in zip file\n", err);
                break;
            }
            if (read == 0)
                break;
            written = mz_stream_os_write(stream, buf, read);
            if (written != read)
            {
                err = mz_stream_os_error(stream);
                printf("Error %d in writing extracted file\n", err);
                break;
            }
        }

        mz_stream_os_close(stream);

        // Set the time of the file that has been unzipped
        if (err == MZ_OK)
            mz_os_set_file_date(write_filename, file_info->dos_date);
    }
    else
    {
        printf("Error opening %s\n", write_filename);
    }

    mz_stream_os_delete(&stream);

    err_close = mz_unzip_entry_close(handle);
    if (err_close != MZ_OK)
        printf("Error %d closing entry in zip file\n", err_close);

    return err;
}

int32_t miniunz_extract_all(void *handle, uint8_t opt_extract_without_path, uint8_t opt_overwrite, const char *password)
{
    int16_t err = MZ_OK;
    

    err = mz_unzip_goto_first_entry(handle);

    if (err != MZ_OK)
    {
        printf("Error %d going to first entry in zip file\n", err);
        return 1;
    }

    while (err == MZ_OK)
    {
        err = miniunz_extract_currentfile(handle, opt_extract_without_path, &opt_overwrite, password);

        if (err != MZ_OK)
            break;

        err = mz_unzip_goto_next_entry(handle);

        if (err != MZ_OK && err != MZ_END_OF_LIST)
        {
            printf("Error %d going to next entry in zip file\n", err);
            return 1;
        }
    }

    return 0;
}

int32_t miniunz_extract_onefile(void *handle, const char *filename, uint8_t opt_extract_without_path, 
    uint8_t opt_overwrite, const char *password)
{
    if (mz_unzip_locate_entry(handle, filename, NULL) != MZ_OK)
    {
        printf("File %s not found in the zip file\n", filename);
        return 2;
    }

    if (miniunz_extract_currentfile(handle, opt_extract_without_path, &opt_overwrite, password) == MZ_OK)
        return 0;

    return 1;
}

#ifndef NOMAIN
int main(int argc, const char *argv[])
{
    void *handle = NULL;
    void *stream = NULL;
    int16_t i = 0;
    uint8_t opt_do_list = 0;
    uint8_t opt_do_extract = 1;
    uint8_t opt_do_extract_withoutpath = 0;
    uint8_t opt_overwrite = 0;
    uint8_t opt_extractdir = 0;
    const char *path = NULL;
    const char *password = NULL;
    const char *directory = NULL;
    const char *filename_to_extract = NULL;
    int err = 0;


    miniunz_banner();
    if (argc == 1)
    {
        miniunz_help();
        return 0;
    }

    // Parse command line options
    for (i = 1; i < argc; i++)
    {
        if ((*argv[i]) == '-')
        {
            const char *p = argv[i]+1;

            while (*p != 0)
            {
                char c = *(p++);
                if ((c == 'l') || (c == 'L'))
                    opt_do_list = 1;
                if ((c == 'v') || (c == 'V'))
                    opt_do_list = 1;
                if ((c == 'x') || (c == 'X'))
                    opt_do_extract = 1;
                if ((c == 'e') || (c == 'E'))
                    opt_do_extract = opt_do_extract_withoutpath = 1;
                if ((c == 'o') || (c == 'O'))
                    opt_overwrite = 1;
                if ((c == 'd') || (c == 'D'))
                {
                    opt_extractdir = 1;
                    directory = argv[i+1];
                }

                if (((c == 'p') || (c == 'P')) && (i+1 < argc))
                {
                    password = argv[i+1];
                    i += 1;
                }
            }

            continue;
        }

        if (path == NULL)
            path = argv[i];
        else if ((filename_to_extract == NULL) && (!opt_extractdir))
            filename_to_extract = argv[i];
    }

    mz_stream_os_create(&stream);

    if (mz_stream_open(stream, path, MZ_STREAM_MODE_READ | MZ_STREAM_MODE_APPEND) != MZ_OK)
    {
        mz_stream_os_delete(&stream);
        printf("Error opening file %s\n", path);
        return 1;
    }

    mz_stream_open(stream, NULL, MZ_STREAM_MODE_READ);

    // Open zip file
    if (path != NULL)
        handle = mz_unzip_open(path, stream);

    if (handle == NULL)
    {
        mz_stream_os_delete(&stream);
        printf("Error opening zip %s\n", path);
        return 1;
    }

    printf("%s opened\n", path);

    // Process command line options
    if (opt_do_list)
    {
        err = miniunz_list(handle);
    }
    else if (opt_do_extract)
    {
        if (opt_extractdir && mz_os_change_dir(directory))
        {
            printf("Error changing into %s, aborting\n", directory);
            exit(-1);
        }

        if (filename_to_extract == NULL)
            err = miniunz_extract_all(handle, opt_do_extract_withoutpath, opt_overwrite, password);
        else
            err = miniunz_extract_onefile(handle, filename_to_extract, opt_do_extract_withoutpath, opt_overwrite, password);
    }

    mz_unzip_close(handle);

    mz_stream_os_close(stream);
    mz_stream_os_delete(&stream);

    return err;
}
#endif
