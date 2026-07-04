/* mz_strm_ppmd.h -- Stream for PPMd compress/decompress
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
      https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_STREAM_PPMD_H
#define MZ_STREAM_PPMD_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/
MZ_EXPORT int32_t mz_stream_ppmd_open(void *stream, const char *filename, int32_t mode);
MZ_EXPORT int32_t mz_stream_ppmd_is_open(void *stream);
MZ_EXPORT int32_t mz_stream_ppmd_read(void *stream, void *buf, int32_t size);
MZ_EXPORT int32_t mz_stream_ppmd_write(void *stream, const void *buf, int32_t size);
MZ_EXPORT int64_t mz_stream_ppmd_tell(void *stream);
MZ_EXPORT int32_t mz_stream_ppmd_seek(void *stream, int64_t offset, int32_t origin);
MZ_EXPORT int32_t mz_stream_ppmd_close(void *stream);
MZ_EXPORT int32_t mz_stream_ppmd_error(void *stream);

MZ_EXPORT int32_t mz_stream_ppmd_get_prop_int64(void *stream, int32_t prop, int64_t *value);
MZ_EXPORT int32_t mz_stream_ppmd_set_prop_int64(void *stream, int32_t prop, int64_t value);

MZ_EXPORT void *mz_stream_ppmd_create(void);
MZ_EXPORT void mz_stream_ppmd_delete(void **stream);

MZ_EXPORT void *mz_stream_ppmd_get_interface(void);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
