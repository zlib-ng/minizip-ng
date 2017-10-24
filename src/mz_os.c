/* mz_os.c -- System functions
   Version 2.2.1, October 23rd, 2017
   part of the MiniZip project

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "mz.h"
#include "mz_strm.h"

#include "mz_os.h"

/***************************************************************************/

int32_t mz_make_dir(const char *path)
{
    int32_t err = MZ_OK;
    int16_t len = 0;
    char *current_dir = NULL;
    char *match = NULL;
    char hold = 0;


    len = (int16_t)strlen(path);
    if (len <= 0)
        return 0;

    current_dir = (char *)malloc(len + 1);
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

    free(current_dir);
    return err;
}

int32_t mz_path_combine(char *path, const char *join, int32_t max_path)
{
    int32_t path_len = 0;

    if (path == NULL || join == NULL || max_path == 0)
        return MZ_PARAM_ERROR;

    path_len = strlen(path);

    if (path_len == 0)
    {
        strncpy(path, join, max_path);
    }
    else
    {
        if (path[path_len - 1] != '\\' && path[path_len - 1] != '/')
            strncat(path, "/", max_path - path_len - 1);
        strncat(path, join, max_path - path_len);
    }

    return MZ_OK;
}
