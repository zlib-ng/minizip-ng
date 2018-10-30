#ifndef MZ_ENCODING_WIN32_H
#define MZ_ENCODING_WIN32_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    int32_t mz_zip_encoding_codepage_to_utf8(const char* source, char* target, int32_t max_target, uint32_t code_page);

/***************************************************************************/

#ifdef __cplusplus
}
#endif

#endif
