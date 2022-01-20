#ifndef MZ_SECURE_API_H
#define MZ_SECURE_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************/

int32_t memcpy_s(void* dest, size_t destMax, const void *src, size_t count);
int32_t strncat_s(char* dest, size_t destMax, const char* src, size_t count);
int32_t strncpy_s(char *dest, size_t destMax, const char *src, size_t count);
size_t strlen_s(const char* s);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif