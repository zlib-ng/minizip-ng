/* miniunz.c
   Version 1.1, February 14h, 2010
   sample part of the MiniZip project

   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html
   Modifications of Unzip for Zip64
     Copyright (C) 2007-2008 Even Rouault
   Modifications for Zip64 support
     Copyright (C) 2009-2010 Mathias Svensson
     http://result42.com

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/


#include "unzip.h"

void do_banner()
{
    printf("MiniUnz 1.01b, demo of zLib + Unz package written by Gilles Vollant\n");
    printf("more info at http://www.winimage.com/zLibDll/minizip.html\n\n");
}

void do_help()
{
    printf("Usage : miniunz [-e] [-x] [-v] [-l] [-o] [-p password] file.zip [file_to_extr.] [-d extractdir]\n\n" \
           "  -e  Extract without pathname (junk paths)\n" \
           "  -x  Extract with pathname\n" \
           "  -v  list files\n" \
           "  -l  list files\n" \
           "  -d  directory to extract into\n" \
           "  -o  overwrite files without prompting\n" \
           "  -p  extract crypted file using password\n\n");
}

void display_zpos64(ZPOS64_T n, int size_char)
{
    /* To avoid compatibility problem we do here the conversion */
    char number[21] = {0};
    int offset = 19;
    int pos_string = 19;
    int size_display_string = 19;

    while (1)
    {
        number[offset] = (char)((n%10) + '0');
        if (number[offset] != '0')
            pos_string = offset;
        n /= 10;
        if (offset == 0)
            break;
        offset--;
    }

    size_display_string -= pos_string;
    while (size_char-- > size_display_string)
        printf(" ");
    printf("%s",&number[pos_string]);
}

int do_list(unzFile uf)
{
    int err = unzGoToFirstFile(uf);
    if (err != UNZ_OK)
    {
        printf("error %d with zipfile in unzGoToFirstFile\n", err);
        return 1;
    }

    printf("  Length  Method     Size Ratio   Date    Time   CRC-32     Name\n");
    printf("  ------  ------     ---- -----   ----    ----   ------     ----\n");

    do
    {
        char filename_inzip[256] = {0};
        unz_file_info64 file_info = {0};
        uLong ratio = 0;
        const char *string_method = NULL;
        char charCrypt = ' ';

        err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0);
        if (err != UNZ_OK)
        {
            printf("error %d with zipfile in unzGetCurrentFileInfo\n", err);
            break;
        }

        if (file_info.uncompressed_size > 0)
            ratio = (uLong)((file_info.compressed_size*100) / file_info.uncompressed_size);

        /* Display a '*' if the file is encrypted */
        if ((file_info.flag & 1) != 0)
            charCrypt = '*';

        if (file_info.compression_method == 0)
            string_method = "Stored";
        else if (file_info.compression_method == Z_DEFLATED)
        {
            uInt iLevel = (uInt)((file_info.flag & 0x6) / 2);
            if (iLevel == 0)
              string_method = "Defl:N";
            else if (iLevel == 1)
              string_method = "Defl:X";
            else if ((iLevel == 2) || (iLevel == 3))
              string_method = "Defl:F"; /* 2:fast , 3 : extra fast*/
        }
        else if (file_info.compression_method == Z_BZIP2ED)
        {
            string_method = "BZip2 ";
        }
        else
            string_method = "Unkn. ";

        display_zpos64(file_info.uncompressed_size, 7);
        printf("  %6s%c", string_method, charCrypt);
        display_zpos64(file_info.compressed_size, 7);
        printf(" %3lu%%  %2.2lu-%2.2lu-%2.2lu  %2.2lu:%2.2lu  %8.8lx   %s\n", ratio,
                (uLong)file_info.tmu_date.tm_mon + 1, (uLong)file_info.tmu_date.tm_mday,
                (uLong)file_info.tmu_date.tm_year % 100,
                (uLong)file_info.tmu_date.tm_hour, (uLong)file_info.tmu_date.tm_min,
                (uLong)file_info.crc, filename_inzip);

        err = unzGoToNextFile(uf);
    }
    while (err == UNZ_OK);

    if (err != UNZ_END_OF_LIST_OF_FILE && err != UNZ_OK) {
        printf("error %d with zipfile in unzGoToNextFile\n", err);
        return err;
    }

    return 0;
}

int main(int argc, const char *argv[])
{
    const char *zipfilename = NULL;
    const char *filename_to_extract = NULL;
    const char *password = NULL;
    int i = 0;
    int ret = 0;
    int opt_do_list = 0;
    int opt_do_extract = 1;
    int opt_do_extract_withoutpath = 0;
    int opt_overwrite = 0;
    int opt_extractdir = 0;
    const char *dirname = NULL;
    unzFile uf = NULL;

    do_banner();
    if (argc == 1)
    {
        do_help();
        return 0;
    }

    /* Parse command line options */
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
                    opt_overwrite=1;
                if ((c == 'd') || (c == 'D'))
                {
                    opt_extractdir = 1;
                    dirname = argv[i+1];
                }

                if (((c == 'p') || (c == 'P')) && (i+1 < argc))
                {
                    password = argv[i+1];
                    i++;
                }
            }
        }
        else
        {
            if (zipfilename == NULL)
                zipfilename = argv[i];
            else if ((filename_to_extract == NULL) && (!opt_extractdir))
                filename_to_extract = argv[i];
        }
    }

    /* Open zip file */
    if (zipfilename != NULL)
    {
#ifdef USEWIN32IOAPI
        zlib_filefunc64_def ffunc;
        fill_win32_filefunc64A(&ffunc);
        uf = unzOpen2_64(zipfilename, &ffunc);
#else
        uf = unzOpen64(zipfilename);
#endif
    }

    if (uf == NULL)
    {
        printf("Cannot open %s\n", zipfilename);
        return 1;
    }

    printf("%s opened\n", zipfilename);

    /* Process command line options */
    if (opt_do_list == 1)
    {
        ret = do_list(uf);
    }
    else if (opt_do_extract == 1)
    {
        if (opt_extractdir && CHDIR(dirname))
        {
            printf("Error changing into %s, aborting\n", dirname);
            exit(-1);
        }

        if (filename_to_extract == NULL)
            ret = do_extract_all(uf, opt_do_extract_withoutpath, opt_overwrite, password);
        else
            ret = do_extract_onefile(uf, filename_to_extract, opt_do_extract_withoutpath, opt_overwrite, password);
    }

    unzClose(uf);
    return ret;
}
