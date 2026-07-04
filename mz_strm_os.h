/* mz_sstrm_os.h -- Stream for filesystem access
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
     https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_STREAM_OS_H
#define MZ_STREAM_OS_H

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/
MZ_EXPORT int32_t mz_stream_os_open(void *stream, const char *path, int32_t mode);
MZ_EXPORT int32_t mz_stream_os_is_open(void *stream);
MZ_EXPORT int32_t mz_stream_os_read(void *stream, void *buf, int32_t size);
MZ_EXPORT int32_t mz_stream_os_write(void *stream, const void *buf, int32_t size);
MZ_EXPORT int64_t mz_stream_os_tell(void *stream);
MZ_EXPORT int32_t mz_stream_os_seek(void *stream, int64_t offset, int32_t origin);
MZ_EXPORT int32_t mz_stream_os_close(void *stream);
MZ_EXPORT int32_t mz_stream_os_error(void *stream);

MZ_EXPORT void *mz_stream_os_create(void);
MZ_EXPORT void mz_stream_os_delete(void **stream);

MZ_EXPORT void *mz_stream_os_get_interface(void);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
