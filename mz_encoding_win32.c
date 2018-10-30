#ifdef _WIN32

#include <Windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#include "mz.h"
#include "mz_encoding_win32.h"

int32_t  mz_zip_encoding_codepage_to_unicode(const char*  source, wchar_t* target, uint32_t code_page)
{
    int32_t cbSize = MultiByteToWideChar(code_page, 0, source, -1, 0, 0);
	if (target)
	{
		MultiByteToWideChar(code_page, 0, source, -1, target, cbSize);
		target[cbSize] = 0;
		return cbSize;
	}
	else
		return cbSize;
}

int32_t mz_zip_encoding_unicode_to_utf8(const wchar_t* source, char* target, int32_t max_target)
{
    int32_t cbSize = WideCharToMultiByte(CP_UTF8, 0, source, -1, 0, 0, 0, 0);
    if (target)
    {
        if (max_target < cbSize)
        {
            cbSize = WideCharToMultiByte(CP_UTF8, 0, source, -1, target, max_target - 1, 0, 0);
            target[max_target] = 0;
        }
        else
        {
            cbSize = WideCharToMultiByte(CP_UTF8, 0, source, -1, target, cbSize, 0, 0);
            target[cbSize] = 0;
        }            
    }
    return cbSize;
}

int32_t mz_zip_encoding_codepage_to_utf8(const char* source, char* target, int32_t max_target, uint32_t code_page)
{
    int32_t cbSize = MultiByteToWideChar(code_page, 0, source, -1, 0, 0);

    wchar_t* lpszUnicode = MZ_ALLOC((cbSize + 1) * sizeof(wchar_t));
    memset(lpszUnicode, 0, (cbSize + 1) * sizeof(wchar_t));

    if (mz_zip_encoding_codepage_to_unicode(source, lpszUnicode, code_page)==0)
    {
        MZ_FREE(lpszUnicode);
        return 0;
    }

    cbSize = mz_zip_encoding_unicode_to_utf8(lpszUnicode, target, max_target);
    MZ_FREE(lpszUnicode);
    return cbSize;
}
#endif