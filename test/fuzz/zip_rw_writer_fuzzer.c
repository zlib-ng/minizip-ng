/* zip_rw_writer_fuzzer.c - Fuzzer for the minizip-ng high level zip writer API.
   part of the minizip-ng project

   Copyright (C) 2026 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

/* Fuzzes the high-level writer API in mz_zip_rw.c, which no existing fuzz
   target reaches (no mz_zip_rw.o in the current fuzz binaries).

   Threat model: the attacker controls the entry metadata an application
   would take from untrusted or user-controlled sources (entry names,
   extra fields, comments, encryption and compression options) and the
   entry payload itself. The writer serialises these into local headers,
   the data area and the central directory; bugs there corrupt archives
   for every downstream reader.

   Shape: option-matrix over the writer knobs followed by a round trip.
   The produced archive is read back with the high-level reader (bounded
   read), optionally re-added with mz_zip_writer_copy_from_reader, and
   when selected the archive is written through the split-disk stream
   layer to a fixed path (files removed after each iteration).

   No seed corpus: the option header has no mutation-resistant gate, plain
   fuzzing crosses the entry checks immediately; the round-trip reader only
   consumes archives the writer itself produced. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_strm_wzaes.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#define MZ_FUZZ_TEST_PWD     "test123"
#define MZ_FUZZ_TEST_NAME    "foo"
#define MZ_FUZZ_TEST_NAME2   "bar"
#define MZ_FUZZ_SPLIT_PATH   "/tmp/mz_rw_writer_fz.zip"
#define MZ_FUZZ_SPLIT_SIZE   16384
#define MZ_FUZZ_META_MAX     512
#define MZ_FUZZ_READ_CAP     (1ll * 1024ll * 1024ll)

/* option bits consumed from the input head */
#define MZ_FUZZ_BIT_ENCRYPT  (1u << 0)
#define MZ_FUZZ_BIT_AES      (1u << 1)
#define MZ_FUZZ_BIT_RAW      (1u << 2)
#define MZ_FUZZ_BIT_ZIP_CD   (1u << 3)
#define MZ_FUZZ_BIT_SPLIT    (1u << 4)
#define MZ_FUZZ_BIT_COPY_CD  (1u << 5)
#define MZ_FUZZ_BIT_2ND      (1u << 6)

/***************************************************************************/

static void mz_fuzz_remove_split_files(void) {
    char path[128];
    int32_t i = 0;

    unlink(MZ_FUZZ_SPLIT_PATH);
    /* split stream names replace the extension with .zNN (see
       mz_stream_split_open_disk in mz_strm_split.c) */
    for (i = 1; i <= 99; i += 1) {
        snprintf(path, sizeof(path), MZ_FUZZ_SPLIT_PATH ".z%02d", i);
        unlink(path);
    }
}

/***************************************************************************/

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    mz_zip_file file_info;
    void *fuzz_stream = NULL;
    void *out_stream = NULL;
    void *out_stream2 = NULL;
    void *writer = NULL;
    void *writer2 = NULL;
    void *reader = NULL;
    mz_zip_file *entry_file_info = NULL;
    uint8_t *payload_buf = NULL;
    const uint8_t *archive_buf = NULL;
    char name[MZ_FUZZ_META_MAX + 1];
    uint8_t comment_buf[MZ_FUZZ_META_MAX];
    uint8_t extra_buf[MZ_FUZZ_META_MAX];
    char chunk[1024];
    uint16_t flags = 0;
    uint16_t method = 0;
    int16_t compress_level = 0;
    uint16_t value16 = 0;
    uint8_t value8 = 0;
    uint8_t opts = 0;
    uint8_t name_len = 0;
    uint16_t meta_len = 0;
    uint16_t comment_len = 0;
    uint16_t extra_len = 0;
    int32_t err = MZ_OK;
    int32_t payload_len = 0;
    int64_t fuzz_pos = 0;
    int64_t fuzz_length = 0;
    int64_t total_read = 0;
    int32_t read_len = 0;
    int32_t archive_len = 0;
    int i = 0;

    fuzz_stream = mz_stream_mem_create();
    if (!fuzz_stream)
        return 1;
    mz_stream_mem_set_buffer(fuzz_stream, (void *)data, (int64_t)size);

    memset(name, 0, sizeof(name));
    memset(comment_buf, 0, sizeof(comment_buf));
    memset(extra_buf, 0, sizeof(extra_buf));

    /* entry flags */
    if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 < 0x08)) {
        if (mz_stream_read_uint16(fuzz_stream, &value16) == MZ_OK)
            flags = value16;
    }

    /* compression method: selector byte picks store, ppmd or a raw id */
    method = MZ_COMPRESS_METHOD_DEFLATE;
    if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 < 0x08)) {
        method = MZ_COMPRESS_METHOD_STORE;
    } else if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 < 0x08)) {
        method = MZ_COMPRESS_METHOD_PPMD;
    } else if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 < 0x08)) {
        if (mz_stream_read_uint16(fuzz_stream, &value16) == MZ_OK)
            method = value16;
    }

    /* compression level */
    compress_level = MZ_COMPRESS_LEVEL_DEFAULT;
    if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 < 0x08)) {
        if (mz_stream_read_uint16(fuzz_stream, &value16) == MZ_OK)
            compress_level = (int16_t)value16;
    }

    /* option bits and entry name length */
    if (mz_stream_read_uint8(fuzz_stream, &opts) != MZ_OK)
        opts = 0;
    if ((mz_stream_read_uint8(fuzz_stream, &value8) == MZ_OK) && (value8 > 0)) {
        name_len = value8;
        mz_stream_read(fuzz_stream, name, name_len);
    }
    if (name[0] == 0)
        strncpy(name, MZ_FUZZ_TEST_NAME, sizeof(name) - 1);

    /* archive comment bytes */
    if ((mz_stream_read_uint16(fuzz_stream, &value16) == MZ_OK)) {
        comment_len = value16 & 0x1FF;
        mz_stream_read(fuzz_stream, comment_buf, comment_len);
    }

    /* entry extra field bytes */
    if ((mz_stream_read_uint16(fuzz_stream, &value16) == MZ_OK)) {
        extra_len = value16 & 0x1FF;
        mz_stream_read(fuzz_stream, extra_buf, extra_len);
    }

    mz_stream_mem_get_buffer_at_current(fuzz_stream, (const void **)&payload_buf);
    fuzz_pos = mz_stream_tell(fuzz_stream);
    mz_stream_mem_get_buffer_length(fuzz_stream, &fuzz_length);
    payload_len = (int32_t)(fuzz_length - fuzz_pos);
    if (payload_len < 0)
        payload_len = 0;


    writer = mz_zip_writer_create();
    if (!writer) {
        mz_stream_mem_delete(&fuzz_stream);
        return 1;
    }

    if (opts & MZ_FUZZ_BIT_ENCRYPT)
        mz_zip_writer_set_password(writer, MZ_FUZZ_TEST_PWD);
    if (opts & MZ_FUZZ_BIT_AES)
        mz_zip_writer_set_aes(writer, 1);
    if (opts & MZ_FUZZ_BIT_RAW)
        mz_zip_writer_set_raw(writer, 1);
    if (opts & MZ_FUZZ_BIT_ZIP_CD)
        mz_zip_writer_set_zip_cd(writer, 1);
    mz_zip_writer_set_compress_method(writer, method);
    mz_zip_writer_set_compress_level(writer, compress_level);
    mz_zip_writer_set_comment(writer, (const char *)comment_buf);

    if (opts & MZ_FUZZ_BIT_SPLIT) {
        err = mz_zip_writer_open_file(writer, MZ_FUZZ_SPLIT_PATH, MZ_FUZZ_SPLIT_SIZE, 0);
    } else {
        out_stream = mz_stream_mem_create();
        if (out_stream)
            err = mz_stream_mem_open(out_stream, NULL, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
        if (out_stream && err == MZ_OK)
            err = mz_zip_writer_open(writer, out_stream, 0);
    }

    if (err == MZ_OK) {
        for (i = 0; i < ((opts & MZ_FUZZ_BIT_2ND) ? 2 : 1); i += 1) {
            memset(&file_info, 0, sizeof(file_info));
            file_info.flag = (uint16_t)(MZ_ZIP_FLAG_UTF8 | flags);
            if (opts & MZ_FUZZ_BIT_ENCRYPT)
                file_info.flag |= MZ_ZIP_FLAG_ENCRYPTED;
            file_info.compression_method = method;
            if ((opts & MZ_FUZZ_BIT_AES) && (file_info.flag & MZ_ZIP_FLAG_ENCRYPTED))
                file_info.aes_version = MZ_AES_VERSION;
            file_info.filename = (i == 0) ? name : MZ_FUZZ_TEST_NAME2;
            file_info.filename_size = (uint16_t)strlen(file_info.filename);
            file_info.comment = comment_buf;
            file_info.comment_size = comment_len;
            file_info.extrafield = extra_buf;
            file_info.extrafield_size = extra_len;

            err = mz_zip_writer_add_buffer(writer, payload_buf, payload_len, &file_info);
            if (err != MZ_OK)
                break;
        }
        mz_zip_writer_close(writer);
    }

    if (opts & MZ_FUZZ_BIT_SPLIT)
        mz_fuzz_remove_split_files();

    mz_zip_writer_delete(&writer);

    /* Round trip: read back what was written (bounded). */
    if (out_stream != NULL) {
        mz_stream_mem_get_buffer(out_stream, (const void **)&archive_buf);
        mz_stream_mem_get_buffer_length(out_stream, &fuzz_length);
        archive_len = (int32_t)fuzz_length;

        if (archive_buf != NULL && archive_len > 0) {
            reader = mz_zip_reader_create();
            if (reader) {
                mz_zip_reader_set_password(reader, MZ_FUZZ_TEST_PWD);
                if (mz_zip_reader_open_buffer(reader, (uint8_t *)archive_buf,
                        archive_len, 0) == MZ_OK) {
                    err = mz_zip_reader_goto_first_entry(reader);
                    while (err == MZ_OK) {
                        err = mz_zip_reader_entry_get_info(reader, &entry_file_info);
                        if (err != MZ_OK)
                            break;
                        mz_zip_reader_entry_is_dir(reader);
                        err = mz_zip_reader_entry_open(reader);
                        if (err != MZ_OK)
                            break;
                        while ((read_len = mz_zip_reader_entry_read(reader, chunk,
                                sizeof(chunk))) > 0) {
                            total_read += read_len;
                            if (total_read > MZ_FUZZ_READ_CAP)
                                break;
                        }
                        mz_zip_reader_entry_close(reader);
                        if (total_read > MZ_FUZZ_READ_CAP)
                            break;
                        err = mz_zip_reader_goto_next_entry(reader);
                    }

                    mz_zip_reader_locate_entry(reader, name, 0);

                    /* Copy the current entry raw from the reader into a
                       second writer (central-directory-driven copy path). */
                    if ((opts & MZ_FUZZ_BIT_COPY_CD) &&
                        (err == MZ_OK || err == MZ_END_OF_LIST)) {
                        mz_zip_reader_goto_first_entry(reader);
                        out_stream2 = mz_stream_mem_create();
                        writer2 = mz_zip_writer_create();
                        if (out_stream2 && writer2 &&
                            mz_stream_mem_open(out_stream2, NULL,
                                MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE) == MZ_OK &&
                            mz_zip_writer_open(writer2, out_stream2, 0) == MZ_OK) {
                            mz_zip_writer_copy_from_reader(writer2, reader);
                            mz_zip_writer_close(writer2);
                        }
                        if (writer2)
                            mz_zip_writer_delete(&writer2);
                        if (out_stream2)
                            mz_stream_mem_delete(&out_stream2);
                    }

                    mz_zip_reader_close(reader);
                }
                mz_zip_reader_delete(&reader);
            }
        }
        mz_stream_mem_delete(&out_stream);
    }

    mz_stream_mem_delete(&fuzz_stream);

    return 0;
}

/***************************************************************************/

#ifdef __cplusplus
}
#endif

