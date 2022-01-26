
#include "mz.h"
#include "mz_secure_api.h"

#define STRING_MAX_LEN (0x7fffffffUL)

/***************************************************************************/

/*
 *  The strncat_s function try to append the first D characters of src to
 *  the end of dest, where D is the least of count and the length of src.
 *  If appending those D characters will fit within dest (whose size is given
 *  as destMax) and still leave room for a null terminator, then those characters
 *  are appended, starting at the original terminating null of dest, and a
 *  new terminating null is appended; otherwise, dest[0] is set to the null
 *  character.
 */
int32_t strncat_s(char* dest, size_t destMax, const char* src, size_t count)
{
    char* header = dest;
    size_t availableSize = destMax;
    const char* overlapGuard = NULL;

    if (destMax == 0 || destMax > STRING_MAX_LEN) {
        return MZ_BUF_ERROR;
    }

    if (dest == NULL || src == NULL) {
        if (dest != NULL) {
            header[0] = '\0';
        }
        return MZ_BUF_ERROR;
    }

    if (dest < src) {
        overlapGuard = src;
        while (availableSize > 0 && *dest != 0) {
            if (dest == overlapGuard) {
                header[0] = '\0';
                return MZ_BUF_ERROR;
            }
            /*seek to string end*/
            dest++;
            availableSize--;
        }

        /* dest unterminated, return error. */
        if (availableSize == 0) {
            header[0] = '\0';
            return MZ_BUF_ERROR;
        }
        /* if available > 0, then excute the strcat operation */
        while ((*dest++ = *src++) != 0 && --availableSize > 0) {
            if (dest == overlapGuard) {
                header[0] = '\0';
                return MZ_BUF_ERROR;
            }
        }
    } else {
        overlapGuard = dest;
        while (availableSize > 0 && *dest != '\0') {
            /*seek to string end, and no need to check overlap*/
            dest++;
            availableSize--;
        }

        /* dest unterminated, return error. */
        if (availableSize == 0) {
            header[0] = '\0';
            return MZ_BUF_ERROR;
        }

        while (count != 0 && availableSize != 0) {
            if (src == overlapGuard) {
                header[0] = '\0';
                return MZ_BUF_ERROR;
            }

            *dest++ = *src++;

            --count;
            --availableSize;
        }
    }

    if (availableSize != 0) {
        *dest = '\0';
    }

    return MZ_OK;
}

size_t strlen_s(const char* s)
{
    return strnlen(s, STRING_MAX_LEN);
}

int32_t strncpy_s(char* dest, size_t destMax, const char* src, size_t count)
{
    const char* overlapGuard = NULL;
    size_t availableSize = destMax;
    char* header = dest;

    if (destMax == 0 || destMax > STRING_MAX_LEN) {
        return MZ_PARAM_ERROR;
    }

    if (dest == NULL || src == NULL) {
        if (dest != NULL) {
            dest[0] = '\0';
        }
        return MZ_PARAM_ERROR;
    }

    if (count > STRING_MAX_LEN || count == 0) {
        dest[0] = '\0'; /*clear dest string*/
        return MZ_PARAM_ERROR;
    }

    if (dest < src) {
        overlapGuard = src;
    }

    while ((*dest++ = *src++) != '\0' && --availableSize > 0) {
        if (src == overlapGuard) {
            header[0] = '\0';
            return MZ_BUF_ERROR;
        }
    }

    return MZ_OK;
}

int32_t memcpy_s(void* dest, size_t destMax, const void* src, size_t count)
{
    if (count == 0) {
        return MZ_OK;
    }

    if (dest == NULL || src == NULL) {
        if (dest) {
            memset(dest, 0, destMax);
        }
        return MZ_PARAM_ERROR;
    }

    if (destMax < count) {
        memset(dest, 0, destMax);
        return MZ_PARAM_ERROR;
    }

    memcpy(dest, src, count);

    return MZ_OK;
}

/***************************************************************************/
