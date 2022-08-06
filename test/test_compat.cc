/* test_compat.cc - Test compatibility layer
   part of the minizip-ng project

   Copyright (C) 2018-2022 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_os.h"
#include "mz_zip.h"
#include "mz_compat.h"

#include <gtest/gtest.h>

#ifdef HAVE_ZLIB
static void test_zip_compat(zipFile zip, const char *filename, int32_t level) {
    int32_t err = ZIP_OK;
    zip_fileinfo file_info;
    const char *buffer = "test data";

    memset(&file_info, 0, sizeof(file_info));
    file_info.dosDate = mz_zip_time_t_to_dos_date(1588561637);

    EXPECT_EQ(err = zipOpenNewFileInZip(zip, filename, &file_info, NULL, 0, NULL, 0, "test local comment",
        Z_DEFLATED, level), ZIP_OK)
        << "failed to open new file in zip (err: " << err << ")";
    if (err != ZIP_OK)
        return;

    EXPECT_EQ(err = zipWriteInFileInZip(zip, buffer, (uint32_t)strlen(buffer)), ZIP_OK)
        << "failed to write to file in zip (err: " << err << ")";

    EXPECT_EQ(err = zipCloseFileInZip(zip), ZIP_OK)
        << "failed to close file in zip (err: " << err << ")";
}

TEST(compat, zip) {
    zipFile zip;

    zip = zipOpen64("compat.zip", APPEND_STATUS_CREATE);
    ASSERT_NE(zip, nullptr) << "cannot create test zip file";

    test_zip_compat(zip, "test.txt", 1);
    test_zip_compat(zip, "test2.txt", 0);

    zipClose(zip, "test global comment");
}

static void test_unzip_compat(unzFile unzip) {
    unz_global_info64 global_info64;
    unz_global_info global_info;
    unz_file_info64 file_info64;
    unz_file_info file_info;
    unz_file_pos file_pos;
    int32_t err = UNZ_OK;
    int32_t bytes_read = 0;
    char comment[120];
    char filename[120];
    char buffer[120];
    const char *test_data = "test data";

    memset(&file_info, 0, sizeof(file_info));
    memset(&file_info64, 0, sizeof(file_info64));
    memset(&global_info, 0, sizeof(global_info));
    memset(&global_info64, 0, sizeof(global_info64));

    comment[0] = 0;
    filename[0] = 0;

    EXPECT_EQ(err = unzGetGlobalComment(unzip, comment, sizeof(comment)), UNZ_OK)
        << "global comment (err: " << err << ")";

    EXPECT_STREQ(comment, "test global comment");

    EXPECT_EQ(err = unzGetGlobalInfo(unzip, &global_info), UNZ_OK)
        << "global info (err: " << err << ")";
    EXPECT_EQ(err = unzGetGlobalInfo64(unzip, &global_info64), UNZ_OK)
        << "global info l info 64-bit (err: " << err << ")";

    EXPECT_EQ(global_info.number_entry, 2)
        << "invalid number of entries";
    EXPECT_EQ(global_info64.number_entry, 2)
        << "invalid number of entries 64-bit";

    EXPECT_EQ(global_info.number_disk_with_CD, 0)
        << "invalid disk with cd";
    EXPECT_EQ(global_info64.number_disk_with_CD, 0)
        << "invalid disk with cd 64-bit";

    EXPECT_EQ(err = unzLocateFile(unzip, "test.txt", (unzFileNameComparer)(void *)1), UNZ_OK)
        << "cannot locate test file (err: " << err << ")";

    EXPECT_EQ(err = unzGoToFirstFile(unzip), UNZ_OK);
    if (err != UNZ_OK)
        return;

    EXPECT_EQ(err = unzGetCurrentFileInfo64(unzip, &file_info64, filename, sizeof(filename), NULL, 0, NULL, 0), UNZ_OK)
        << "failed to get current file info 64-bit (err: " << err << ")";
    EXPECT_EQ(err = unzOpenCurrentFile(unzip), UNZ_OK)
        << "failed to open current file (err: " << err << ")";

    EXPECT_EQ(bytes_read = unzReadCurrentFile(unzip, buffer, sizeof(buffer)), (int32_t)strlen(test_data))
        << "failed to read zip entry data (err: " << err << ")";

    EXPECT_EQ(unzEndOfFile(unzip), 1)
        << "end of zip not reported correctly";

    EXPECT_EQ(err = unzCloseCurrentFile(unzip), UNZ_OK)
        << "failed to close current file (err: " << err << ")";

    EXPECT_EQ(unztell(unzip), bytes_read)
        << "unzip position not reported correctly";

    EXPECT_EQ(err = unzGoToNextFile(unzip), UNZ_OK);
    if (err != UNZ_OK)
        return;

    comment[0] = 0;
    EXPECT_EQ(err = unzGetCurrentFileInfo(unzip, &file_info, filename, sizeof(filename), NULL, 0, comment, sizeof(comment)), UNZ_OK)
        << "failed to get current file info (err: " << err << ")";

    EXPECT_STREQ(comment, "test local comment");

    EXPECT_EQ(err = unzGetFilePos(unzip, &file_pos), UNZ_OK)
        << "unexpected file position (err: " << err << ")";

    EXPECT_EQ(file_pos.num_of_file, 1)
        << "invalid file position";

    EXPECT_GT(unzGetOffset(unzip), 0)
        << "invalid offset";

    EXPECT_EQ(err = unzSeek64(unzip, 0, SEEK_SET), UNZ_OK)
        << "cannot seek to beginning (err: " << err << ")";

    EXPECT_EQ(err = unzGoToNextFile(unzip), UNZ_END_OF_LIST_OF_FILE)
        << "failed to reach end of list of files (err: " << err << ")";

    EXPECT_EQ(err = unzSeek64(unzip, 0, SEEK_SET), UNZ_PARAMERROR)
        << "cannot seek to beginning (err: " << err << ")";

    unzCloseCurrentFile(unzip);
}

#ifndef MZ_FILE32_API
#  ifndef NO_FSEEKO
#    define ftello64 ftello
#    define fseeko64 fseeko
#  elif defined(_MSC_VER) && (_MSC_VER >= 1400)
#    define ftello64 _ftelli64
#    define fseeko64 _fseeki64
#  endif
#endif
#ifndef ftello64
#  define ftello64 ftell
#endif
#ifndef fseeko64
#  define fseeko64 fseek
#endif

static void *ZCALLBACK fopen_file_func(void *opaque, const char *filename, int mode) {
    FILE* file = NULL;
    const char* mode_fopen = NULL;

    if ((mode & ZLIB_FILEFUNC_MODE_READWRITEFILTER)==ZLIB_FILEFUNC_MODE_READ)
        mode_fopen = "rb";
    else if (mode & ZLIB_FILEFUNC_MODE_EXISTING)
        mode_fopen = "r+b";
    else if (mode & ZLIB_FILEFUNC_MODE_CREATE)
        mode_fopen = "wb";

    if ((filename != NULL) && (mode_fopen != NULL))
        file = fopen(filename, mode_fopen);

    return file;
}

static unsigned long ZCALLBACK fread_file_func(void *opaque, void *stream, void *buf, unsigned long size) {
    return (unsigned long)fread(buf, 1, (size_t)size, (FILE *)stream);
}

static unsigned long ZCALLBACK fwrite_file_func(void *opaque, void *stream, const void *buf, unsigned long size) {
    return (unsigned long)fwrite(buf, 1, (size_t)size, (FILE *)stream);
}

static long ZCALLBACK ftell_file_func(void *opaque, void *stream) {
    return ftell((FILE *)stream);
}

static ZPOS64_T ZCALLBACK ftell64_file_func(void *opaque, void *stream) {
    return ftello64((FILE *)stream);
}

static long ZCALLBACK fseek_file_func(void *opaque, void *stream, unsigned long offset, int origin) {
    int fseek_origin = 0;
    long ret = 0;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR:
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END:
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET:
        fseek_origin = SEEK_SET;
        break;
    default:
        return -1;
    }
    if (fseek((FILE *)stream, offset, fseek_origin) != 0)
        ret = -1;
    return ret;
}

static long ZCALLBACK fseek64_file_func(void *opaque, void *stream, ZPOS64_T offset, int origin) {
    int fseek_origin = 0;
    long ret = 0;
    switch (origin)
    {
    case ZLIB_FILEFUNC_SEEK_CUR:
        fseek_origin = SEEK_CUR;
        break;
    case ZLIB_FILEFUNC_SEEK_END:
        fseek_origin = SEEK_END;
        break;
    case ZLIB_FILEFUNC_SEEK_SET:
        fseek_origin = SEEK_SET;
        break;
    default:
        return -1;
    }
    if (fseeko64((FILE *)stream, offset, fseek_origin) != 0)
        ret = -1;
    return ret;
}

static int ZCALLBACK fclose_file_func(void *opaque, void *stream) {
    return fclose((FILE *)stream);
}

static int ZCALLBACK ferror_file_func(void *opaque, void *stream) {
    return ferror((FILE *)stream);
}

void fill_ioapi32_filefunc(zlib_filefunc_def *pzlib_filefunc_def) {
    pzlib_filefunc_def->zopen_file = fopen_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell_file = ftell_file_func;
    pzlib_filefunc_def->zseek_file = fseek_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

void fill_ioapi64_filefunc(zlib_filefunc64_def *pzlib_filefunc_def) {
    pzlib_filefunc_def->zopen64_file = (open64_file_func)fopen_file_func;
    pzlib_filefunc_def->zread_file = fread_file_func;
    pzlib_filefunc_def->zwrite_file = fwrite_file_func;
    pzlib_filefunc_def->ztell64_file = ftell64_file_func;
    pzlib_filefunc_def->zseek64_file = fseek64_file_func;
    pzlib_filefunc_def->zclose_file = fclose_file_func;
    pzlib_filefunc_def->zerror_file = ferror_file_func;
    pzlib_filefunc_def->opaque = NULL;
}

TEST(compat, unzip) {
    unzFile unzip;

    unzip = unzOpen("compat.zip");
    ASSERT_NE(unzip, nullptr) << "cannot open test zip file";

    test_unzip_compat(unzip);
    unzClose(unzip);
}

TEST(compat, unzip32) {
    unzFile unzip;
    zlib_filefunc_def zlib_filefunc_def;

    fill_ioapi32_filefunc(&zlib_filefunc_def);
    unzip = unzOpen2("compat.zip", &zlib_filefunc_def);
    ASSERT_NE(unzip, nullptr) << "cannot open test zip file";

    test_unzip_compat(unzip);
    unzClose(unzip);
}

TEST(compat, unzip64) {
    unzFile unzip;
    zlib_filefunc64_def zlib_filefunc_def;

    fill_ioapi64_filefunc(&zlib_filefunc_def);
    unzip = unzOpen2_64("compat.zip", &zlib_filefunc_def);
    ASSERT_NE(unzip, nullptr) << "cannot open test zip file";

    test_unzip_compat(unzip);
    unzClose(unzip);
}
#endif
