/* mz_secure_api.h -- Secure string and memory API
   part of the minizip-ng project

   https://github.com/Maxar-Corp/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include "mz.h"
#include "mz_secure_api.h"

/**
 * NAME
 *    strncat_s
 *
 * DESCRIPTION
 *    This function concatenates at most count bytes
 *    from src to destination string
 *
 * INPUT PARAMETERS
 *    dest      pointer to string that will be concatenated to.
 *
 *    destMax   maximum length of the dest buffer
 *
 *    src       pointer to the memory that will be concatenated from.
 *
 *    count     maximum number bytes of src to concatenate
 *
 * RETURN VALUE
 *    MZ_OK             successful operation
 *    MZ_PARAM_ERROR    parameter error
 *    MZ_BUF_ERROR      buffer error
 *
 * COMMENTS
 *    dest is null terminated on error if space is available
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
        return MZ_PARAM_ERROR;
    }

    if (dest < src) {
        overlapGuard = src;
        while (availableSize > 0 && *dest != 0) {
            if (dest == overlapGuard) {
                header[0] = '\0';
                return MZ_BUF_ERROR;
            }
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
        while (availableSize > 0 && *dest != '\0') {
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

/**
 * NAME
 *    strnlen_s
 *
 * DESCRIPTION
 *    This function returns the length of the input string or
 *    0 if error.
 *
 * INPUT PARAMETERS
 *    s         pointer to the input string
 *    maxLen    maximum length of the string
 *
 * RETURN VALUE
 *    length of the string or 0 if error
 *
 */
size_t strnlen_s(const char* s, size_t maxlen)
{
    size_t len;

    if (s == NULL || maxlen > STRING_MAX_LEN) {
        return 0;
    }

    for (len = 0; len < maxlen; len++, s++) {
        if (!*s) {
            break;
        }
    }

    return len;
}

/**
 * NAME
 *    strncpy_s
 *
 * DESCRIPTION
 *    This function copies at most count bytes from src to dest, up to
 *    destMax including terminating null if space is available.
 *
 * INPUT PARAMETERS
 *    dest      pointer to memory that will be copied from src.
 *
 *    destMax   maximum length of the dest buffer
 *
 *    src       pointer to the memory that will be copied to dest
 *
 *    count     maximum number bytes of src to copy
 *
 * RETURN VALUE
 *    MZ_OK             successful operation
 *    MZ_PARAM_ERROR    parameter error
 *    MZ_BUF_ERROR      buffer overlap error
 *
 * COMMENTS
 *    dest is null terminated on error if space is available
 */
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
        dest[0] = '\0';
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

/**
 * NAME
 *    memcpy_s
 *
 * DESCRIPTION
 *    This function copies at most count bytes from src to dest, up to
 *    destMax.
 *
 * INPUT PARAMETERS
 *    dest      pointer to memory that will be copied from src.
 *
 *    destMax   maximum length of the dest buffer
 *
 *    src       pointer to the memory that will be copied to dest
 *
 *    count      maximum number bytes of src to copy
 *
 * RETURN VALUE
 *    MZ_OK             successful operation
 *    MZ_PARAM_ERROR    parameter error
 */
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
