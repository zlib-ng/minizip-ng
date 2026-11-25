/* zip_rw_reader_fuzzer.c - Fuzzer for the minizip-ng high level zip reader API.
   part of the minizip-ng project

   Copyright (C) 2026 Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

/* Fuzzes the high-level reader API in mz_zip_rw.c. No existing fuzz target
   reaches this code: the fuzz binaries contain no mz_zip_rw.o at all because
   nothing references it and static archives drop unreferenced objects.

   Threat model: the whole archive buffer is untrusted, exactly like an
   application calling mz_zip_reader_open_buffer() on a downloaded zip.
   The attacker controls names, extra fields, comments, encryption flags,
   compression methods and all offsets/sizes in the archive.

   Exercised here:
     - archive open, central directory parsing, recovery mode
     - entry enumeration, info, hash extra fields, directories
     - bounded entry decompression (8 MiB cap) including pkcrypt/wzaes
       entries via a fixed password, mirroring unzip_fuzzer
     - entry_save_buffer with its documented allocation contract
       (buffer of file_info->uncompressed_size, capped at 64 KiB)
     - locate_entry case-sensitive and case-insensitive lookups
     - unzip_cd (zipped central directory)
     - save_all extraction into a fixed directory: entry-name resolution,
       directory creation, symlink/traversal defenses (mz_path_combine_safe,
       mz_dir_has_unsafe_symlink) and the posix file stream layers
     - extraction directory cleanup between iterations, lstat-safe so
       attacker-controlled symlinks are never followed */

#include <dirent.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_os.h"
#include "mz_zip.h"
#include "mz_zip_rw.h"

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

#define MZ_FUZZ_TEST_PWD  "test123"
#define MZ_FUZZ_TEST_NAME "foo"
#define MZ_FUZZ_TEST_NAMEUC "FOO"
#define MZ_FUZZ_DEST_DIR  "/tmp/mz_rw_reader_fz"
#define MZ_FUZZ_READ_CAP  (8ll * 1024ll * 1024ll)
#define MZ_FUZZ_SAVE_CAP  (64 * 1024)

/***************************************************************************/

static void mz_fuzz_remove_tree(const char *path) {
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    struct stat st;
    char child[PATH_MAX];

    /* lstat so attacker-controlled symlinks are never followed */
    if (lstat(path, &st) != 0)
        return;
    if (!S_ISDIR(st.st_mode)) {
        unlink(path);
        return;
    }

    dir = opendir(path);
    if (!dir) {
        unlink(path);
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        mz_fuzz_remove_tree(child);
    }

    closedir(dir);
    rmdir(path);
}

/***************************************************************************/

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *reader = NULL;
    mz_zip_file *file_info = NULL;
    uint8_t *save_buf = NULL;
    char chunk[1024];
    const char *archive_comment = NULL;
    uint16_t hash_algorithm = 0;
    uint16_t hash_digest_size = 0;
    uint8_t hash_digest[MZ_HASH_MAX_SIZE];
    uint8_t zip_cd = 0;
    uint8_t raw = 0;
    int32_t err = MZ_OK;
    int64_t total_read = 0;
    int32_t read_len = 0;
    int32_t save_len = 0;

    if (size < 4)
        return 0;

    reader = mz_zip_reader_create();
    if (!reader)
        return 1;

    /* Mirror unzip_fuzzer: recovery enabled on a slice of the corpus. */
    mz_zip_reader_set_recover(reader, (size & 0xE0) == 0xE0);
    mz_zip_reader_set_password(reader, MZ_FUZZ_TEST_PWD);

    if (mz_zip_reader_open_buffer(reader, (uint8_t *)data, (int32_t)size, 0) == MZ_OK) {
        mz_zip_reader_get_comment(reader, &archive_comment);
        mz_zip_reader_get_zip_cd(reader, &zip_cd);
        mz_zip_reader_get_raw(reader, &raw);

        err = mz_zip_reader_goto_first_entry(reader);
        while (err == MZ_OK) {
            err = mz_zip_reader_entry_get_info(reader, &file_info);
            if (err != MZ_OK)
                break;

            mz_zip_reader_entry_is_dir(reader);

            err = mz_zip_reader_entry_open(reader);
            if (err != MZ_OK)
                break;

            mz_zip_reader_entry_get_first_hash(reader, &hash_algorithm, &hash_digest_size);
            if (hash_digest_size > 0 && hash_digest_size <= MZ_HASH_MAX_SIZE)
                mz_zip_reader_entry_get_hash(reader, hash_algorithm, hash_digest,
                    hash_digest_size);

            /* Bounded decompression: stop after the cap so a decompression
               bomb cannot dominate the run (fuzzer hygiene, not a product
               guarantee). */
            while ((read_len = mz_zip_reader_entry_read(reader, chunk, sizeof(chunk))) > 0) {
                total_read += read_len;
                if (total_read > MZ_FUZZ_READ_CAP)
                    break;
            }
            mz_zip_reader_entry_close(reader);
            if (total_read > MZ_FUZZ_READ_CAP)
                break;

            /* Allocation contract of entry_save_buffer: exactly the
               uncompressed size reported for the entry. */
            save_len = mz_zip_reader_entry_save_buffer_length(reader);
            if (save_len > 0 && save_len <= MZ_FUZZ_SAVE_CAP) {
                save_buf = malloc(save_len);
                if (save_buf) {
                    mz_zip_reader_entry_save_buffer(reader, save_buf, save_len);
                    free(save_buf);
                    save_buf = NULL;
                }
            }

            err = mz_zip_reader_goto_next_entry(reader);
        }

        mz_zip_reader_locate_entry(reader, MZ_FUZZ_TEST_NAME, 0);
        mz_zip_reader_locate_entry(reader, MZ_FUZZ_TEST_NAMEUC, 1);
        mz_zip_reader_unzip_cd(reader);

        /* Extract everything into a fixed directory and clean it up. */
        mz_dir_make(MZ_FUZZ_DEST_DIR);
        mz_zip_reader_save_all(reader, MZ_FUZZ_DEST_DIR);
        mz_fuzz_remove_tree(MZ_FUZZ_DEST_DIR);

        mz_zip_reader_close(reader);
    }

    mz_zip_reader_delete(&reader);

    return 0;
}

/***************************************************************************/

#ifdef __cplusplus
}
#endif

