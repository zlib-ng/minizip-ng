/* mz_secure_api.h -- Secure string and memory API
   part of the minizip-ng project

   https://github.com/Maxar-Corp/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#ifndef MZ_SECURE_API_H
#define MZ_SECURE_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define STRING_MAX_LEN (0x7fffffffUL)

/***************************************************************************/

int32_t memcpy_s(void* dest, size_t destMax, const void *src, size_t count);
int32_t strncat_s(char* dest, size_t destMax, const char* src, size_t count);
int32_t strncpy_s(char *dest, size_t destMax, const char *src, size_t count);
size_t strnlen_s(const char* s, size_t maxlen);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif