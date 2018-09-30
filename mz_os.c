/* mz_os.c -- System functions
   Version 2.5.4, September 30, 2018
   part of the MiniZip project

   Copyright (C) 2010-2018 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "mz.h"
#include "mz_os.h"
#include "mz_strm.h"
#include "mz_strm_crc32.h"

/***************************************************************************/

static uint32_t mz_encoding_codepage437_to_utf8[256] = {
    0x000000, 0xba98e2, 0xbb98e2, 0xa599e2, 0xa699e2, 0xa399e2, 0xa099e2, 0xa280e2,
    0x9897e2, 0x8b97e2, 0x9997e2, 0x8299e2, 0x8099e2, 0xaa99e2, 0xab99e2, 0xbc98e2,
    0xba96e2, 0x8497e2, 0x9586e2, 0xbc80e2, 0x00b6c2, 0x00a7c2, 0xac96e2, 0xa886e2,
    0x9186e2, 0x9386e2, 0x9286e2, 0x9086e2, 0x9f88e2, 0x9486e2, 0xb296e2, 0xbc96e2,
    0x000020, 0x000021, 0x000022, 0x000023, 0x000024, 0x000025, 0x000026, 0x000027,
    0x000028, 0x000029, 0x00002a, 0x00002b, 0x00002c, 0x00002d, 0x00002e, 0x00002f,
    0x000030, 0x000031, 0x000032, 0x000033, 0x000034, 0x000035, 0x000036, 0x000037,
    0x000038, 0x000039, 0x00003a, 0x00003b, 0x00003c, 0x00003d, 0x00003e, 0x00003f,
    0x000040, 0x000041, 0x000042, 0x000043, 0x000044, 0x000045, 0x000046, 0x000047,
    0x000048, 0x000049, 0x00004a, 0x00004b, 0x00004c, 0x00004d, 0x00004e, 0x00004f,
    0x000050, 0x000051, 0x000052, 0x000053, 0x000054, 0x000055, 0x000056, 0x000057,
    0x000058, 0x000059, 0x00005a, 0x00005b, 0x00005c, 0x00005d, 0x00005e, 0x00005f,
    0x000060, 0x000061, 0x000062, 0x000063, 0x000064, 0x000065, 0x000066, 0x000067,
    0x000068, 0x000069, 0x00006a, 0x00006b, 0x00006c, 0x00006d, 0x00006e, 0x00006f,
    0x000070, 0x000071, 0x000072, 0x000073, 0x000074, 0x000075, 0x000076, 0x000077,
    0x000078, 0x000079, 0x00007a, 0x00007b, 0x00007c, 0x00007d, 0x00007e, 0x828ce2,
    0x0087c3, 0x00bcc3, 0x00a9c3, 0x00a2c3, 0x00a4c3, 0x00a0c3, 0x00a5c3, 0x00a7c3,
    0x00aac3, 0x00abc3, 0x00a8c3, 0x00afc3, 0x00aec3, 0x00acc3, 0x0084c3, 0x0085c3,
    0x0089c3, 0x00a6c3, 0x0086c3, 0x00b4c3, 0x00b6c3, 0x00b2c3, 0x00bbc3, 0x00b9c3,
    0x00bfc3, 0x0096c3, 0x009cc3, 0x00a2c2, 0x00a3c2, 0x00a5c2, 0xa782e2, 0x0092c6,
    0x00a1c3, 0x00adc3, 0x00b3c3, 0x00bac3, 0x00b1c3, 0x0091c3, 0x00aac2, 0x00bac2,
    0x00bfc2, 0x908ce2, 0x00acc2, 0x00bdc2, 0x00bcc2, 0x00a1c2, 0x00abc2, 0x00bbc2,
    0x9196e2, 0x9296e2, 0x9396e2, 0x8294e2, 0xa494e2, 0xa195e2, 0xa295e2, 0x9695e2,
    0x9595e2, 0xa395e2, 0x9195e2, 0x9795e2, 0x9d95e2, 0x9c95e2, 0x9b95e2, 0x9094e2,
    0x9494e2, 0xb494e2, 0xac94e2, 0x9c94e2, 0x8094e2, 0xbc94e2, 0x9e95e2, 0x9f95e2,
    0x9a95e2, 0x9495e2, 0xa995e2, 0xa695e2, 0xa095e2, 0x9095e2, 0xac95e2, 0xa795e2,
    0xa895e2, 0xa495e2, 0xa595e2, 0x9995e2, 0x9895e2, 0x9295e2, 0x9395e2, 0xab95e2,
    0xaa95e2, 0x9894e2, 0x8c94e2, 0x8896e2, 0x8496e2, 0x8c96e2, 0x9096e2, 0x8096e2,
    0x00b1ce, 0x009fc3, 0x0093ce, 0x0080cf, 0x00a3ce, 0x0083cf, 0x00b5c2, 0x0084cf,
    0x00a6ce, 0x0098ce, 0x00a9ce, 0x00b4ce, 0x9e88e2, 0x0086cf, 0x00b5ce, 0xa988e2,
    0xa189e2, 0x00b1c2, 0xa589e2, 0xa489e2, 0xa08ce2, 0xa18ce2, 0x00b7c3, 0x8889e2,
    0x00b0c2, 0x9988e2, 0x00b7c2, 0x9a88e2, 0xbf81e2, 0x00b2c2, 0xa096e2, 0x00a0c2
};

/***************************************************************************/

int32_t mz_path_combine(char *path, const char *join, int32_t max_path)
{
    int32_t path_len = 0;

    if (path == NULL || join == NULL || max_path == 0)
        return MZ_PARAM_ERROR;

    path_len = strlen(path);

    if (path_len == 0)
    {
        strncpy(path, join, max_path - 1);
        path[max_path - 1] = 0;
    }
    else
    {
        if (path[path_len - 1] != '\\' && path[path_len - 1] != '/')
            strncat(path, "/", max_path - path_len - 1);
        strncat(path, join, max_path - path_len);
    }

    return MZ_OK;
}

int32_t mz_path_compare_wc(const char *path, const char *wildcard, uint8_t ignore_case)
{
    while (*path != 0)
    {
        switch (*wildcard)
        {
        case '*':

            if (*(wildcard + 1) == 0)
                return MZ_OK;

            while (*path != 0)
            {
                if (mz_path_compare_wc(path, (wildcard + 1), ignore_case) == MZ_OK)
                    return MZ_OK;

                path += 1;
            }

            return MZ_EXIST_ERROR;

        default:
            // Ignore differences in path slashes on platforms
            if ((*path == '\\' && *wildcard == '/') || (*path == '/' && *wildcard == '\\'))
                break;

            if (ignore_case)
            {
                if (tolower(*path) != tolower(*wildcard))
                    return MZ_EXIST_ERROR;
            }
            else
            {
                if (*path != *wildcard)
                    return MZ_EXIST_ERROR;
            }

            break;
        }

        path += 1;
        wildcard += 1;
    }

    if ((*wildcard != 0) && (*wildcard != '*'))
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_path_resolve(const char *path, char *output, int32_t max_output)
{
    const char *source = path;
    const char *check = output;
    char *target = output;

    if (max_output <= 0)
        return MZ_PARAM_ERROR;

    while (*source != 0 && max_output > 1)
    {
        check = source;
        if ((*check == '\\') || (*check == '/'))
            check += 1;

        if ((source == path) || (check != source))
        {
            // Skip double paths
            if ((*check == '\\') || (*check == '/'))
            {
                source += 1;
                continue;
            }
            if ((*check != 0) && (*check == '.'))
            {
                check += 1;

                // Remove current directory . if at end of string
                if ((*check == 0) && (source != path))
                {
                    // Copy last slash
                    *target = *source;
                    target += 1;
                    max_output -= 1;
                    source += (check - source);
                    continue;
                }

                // Remove current directory . if not at end of string
                if ((*check == 0) || (*check == '\\' || *check == '/'))
                {
                    // Only proceed if .\ is not entire string
                    if (check[1] != 0 || (path != source))
                    {
                        source += (check - source);
                        continue;
                    }
                }

                // Go to parent directory ..
                if ((*check != 0) || (*check == '.'))
                {
                    check += 1;
                    if ((*check == 0) || (*check == '\\' || *check == '/'))
                    {
                        source += (check - source);

                        // Search backwards for previous slash
                        if (target != output)
                        {
                            target -= 1;
                            do
                            {
                                if ((*target == '\\') || (*target == '/'))
                                    break;

                                target -= 1;
                                max_output += 1;
                            }
                            while (target > output);
                        }

                        if ((target == output) && (*source != 0))
                            source += 1;
                        if ((*target == '\\' || *target == '/') && (*source == 0))
                            target += 1;

                        *target = 0;
                        continue;
                    }
                }
            }
        }

        *target = *source;

        source += 1;
        target += 1;
        max_output -= 1;
    }

    *target = 0;

    if (*path == 0)
        return MZ_INTERNAL_ERROR;

    return MZ_OK;
}

int32_t mz_path_remove_filename(char *path)
{
    char *path_ptr = NULL;

    if (path == NULL)
        return MZ_PARAM_ERROR;

    path_ptr = path + strlen(path) - 1;

    while (path_ptr > path)
    {
        if ((*path_ptr == '/') || (*path_ptr == '\\'))
        {
            *path_ptr = 0;
            break;
        }

        path_ptr -= 1;
    }
    return MZ_OK;
}

int32_t mz_path_get_filename(const char *path, const char **filename)
{
    const char *match = NULL;

    if (path == NULL || filename == NULL)
        return MZ_PARAM_ERROR;

    *filename = NULL;

    for (match = path; *match != 0; match += 1)
    {
        if ((*match == '\\') || (*match == '/'))
            *filename = match + 1;
    }

    if (*filename == NULL)
        return MZ_EXIST_ERROR;

    return MZ_OK;
}

int32_t mz_dir_make(const char *path)
{
    int32_t err = MZ_OK;
    int16_t len = 0;
    char *current_dir = NULL;
    char *match = NULL;
    char hold = 0;


    len = (int16_t)strlen(path);
    if (len <= 0)
        return 0;

    current_dir = (char *)MZ_ALLOC(len + 1);
    if (current_dir == NULL)
        return MZ_MEM_ERROR;

    strcpy(current_dir, path);

    if (current_dir[len - 1] == '/')
        current_dir[len - 1] = 0;

    err = mz_os_make_dir(current_dir);
    if (err != MZ_OK)
    {
        match = current_dir + 1;
        while (1)
        {
            while (*match != 0 && *match != '\\' && *match != '/')
                match += 1;
            hold = *match;
            *match = 0;

            err = mz_os_make_dir(current_dir);
            if (err != MZ_OK)
                break;
            if (hold == 0)
                break;

            *match = hold;
            match += 1;
        }
    }

    MZ_FREE(current_dir);
    return err;
}

int32_t mz_file_get_crc(const char *path, uint32_t *result_crc)
{
    void *stream = NULL;
    void *crc32_stream = NULL;
    int32_t read = 0;
    int32_t err = MZ_OK;
    uint8_t buf[16384];

    mz_stream_os_create(&stream);

    err = mz_stream_os_open(stream, path, MZ_OPEN_MODE_READ);

    mz_stream_crc32_create(&crc32_stream);
    mz_stream_crc32_open(crc32_stream, NULL, MZ_OPEN_MODE_READ);

    mz_stream_set_base(crc32_stream, stream);

    if (err == MZ_OK)
    {
        do
        {
            read = mz_stream_crc32_read(crc32_stream, buf, sizeof(buf));

            if (read < 0)
            {
                err = read;
                break;
            }
        }
        while ((err == MZ_OK) && (read > 0));

        mz_stream_os_close(stream);
    }

    mz_stream_crc32_close(crc32_stream);
    *result_crc = mz_stream_crc32_get_value(crc32_stream);
    mz_stream_crc32_delete(&crc32_stream);

    mz_stream_os_delete(&stream);

    return err;
}

int32_t mz_encoding_cp437_to_utf8(const char *source, char *target, int32_t max_target)
{
    uint32_t utf8_char = 0;
    uint8_t utf8_byte = 0;
    uint8_t cp437_char = 0;
    int32_t x = 0;
    int32_t written = 0;

    // Convert ibm codepage 437 encoding to utf-8
    while (*source != 0)
    {
        cp437_char = *source;
        source += 1;
        utf8_char = mz_encoding_codepage437_to_utf8[cp437_char];
        for (x = 0; x < 32; x += 8)
        {
            utf8_byte = (uint8_t)(utf8_char >> x);
            if (x > 0 && utf8_byte == 0)
                continue;
            if (max_target <= 1)
                break;
            target[written] = utf8_byte;
            written += 1;
            max_target -= 1;
        }
    }

    if (max_target > 0)
    {
        target[written] = 0;
        written += 1;
    }

    return written;
}

/***************************************************************************/
