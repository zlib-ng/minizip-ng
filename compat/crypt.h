/* crypt.h -- base code for crypt/uncrypt ZIPfile
   Version 1.01e, February 12th, 2005

   Copyright (C) 1998-2005 Gilles Vollant

   This code is a modified version of crypting code in Infozip distribution

   The encryption/decryption parts of this source code (as opposed to the
   non-echoing password parts) were originally written in Europe.  The
   whole source package can be freely distributed, including from the USA.
   (Prior to January 2000, re-export from the US was a violation of US law.)

   This encryption code is a direct transcription of the algorithm from
   Roger Schlafly, described by Phil Katz in the file appnote.txt.  This
   file (appnote.txt) is distributed with the PKZIP program (even in the
   version without encryption capabilities).

   If you don't need crypting in your application, just define symbols
   NOCRYPT and NOUNCRYPT.

   This code support the "Traditional PKWARE Encryption".

   The new AES encryption added on Zip format by Winzip (see the page
   http://www.winzip.com/aes_info.htm ) and PKWare PKZip 5.x Strong
   Encryption is not supported.
*/

#ifndef ZLIB_VERNUM
/* No zlib */
typedef uint32_t z_crc_t;
#elif (ZLIB_VERNUM & 0xf != 0xf) && (ZLIB_VERNUM < 0x1270)
/* Define z_crc_t in zlib 1.2.6 and less */
typedef unsigned long z_crc_t;
#elif (ZLIB_VERNUM & 0xf == 0xf) && (ZLIB_VERNUM < 0x12df)
/* Define z_crc_t in zlib-ng 2.0.7 and less */
typedef unsigned int z_crc_t;
#endif

#define CRC32(c, b) ((*(pcrc_32_tab + (((int)(c) ^ (b)) & 0xff))) ^ ((c) >> 8))

/***************************************************************************/
/* Return the next byte in the pseudo-random sequence */

static int decrypt_byte(unsigned long *pkeys, const z_crc_t *pcrc_32_tab) {
    unsigned temp; /* POTENTIAL BUG:  temp*(temp^1) may overflow in an
                    * unpredictable manner on 16-bit systems; not a problem
                    * with any known compiler so far, though */

    (void)pcrc_32_tab;
    temp = ((unsigned)(*(pkeys + 2)) & 0xffff) | 2;
    return (int)(((temp * (temp ^ 1)) >> 8) & 0xff);
}

/***************************************************************************/
/* Update the encryption keys with the next byte of plain text */

static int update_keys(unsigned long *pkeys, const z_crc_t *pcrc_32_tab, int c) {
    (*(pkeys + 0)) = CRC32((*(pkeys + 0)), c);
    (*(pkeys + 1)) += (*(pkeys + 0)) & 0xff;
    (*(pkeys + 1)) = (*(pkeys + 1)) * 134775813L + 1;
    {
        register int keyshift = (int)((*(pkeys + 1)) >> 24);
        (*(pkeys + 2)) = CRC32((*(pkeys + 2)), keyshift);
    }
    return c;
}

/***************************************************************************/
/* Initialize the encryption keys and the random header according to the password. */

static void init_keys(const char *passwd, unsigned long *pkeys, const z_crc_t *pcrc_32_tab) {
    *(pkeys + 0) = 305419896L;
    *(pkeys + 1) = 591751049L;
    *(pkeys + 2) = 878082192L;
    while (*passwd != '\0') {
        update_keys(pkeys, pcrc_32_tab, (int)*passwd);
        passwd++;
    }
}

#define zdecode(pkeys, pcrc_32_tab, c) (update_keys(pkeys, pcrc_32_tab, c ^= decrypt_byte(pkeys, pcrc_32_tab)))

#define zencode(pkeys, pcrc_32_tab, c, t)                                                                              \
    (t = decrypt_byte(pkeys, pcrc_32_tab), update_keys(pkeys, pcrc_32_tab, c), (Byte)t ^ (c))
