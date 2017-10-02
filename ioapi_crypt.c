/* ioapi_crypt.c -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   This version of ioapi is designed to access memory rather than files.
   We do use a region of memory to put data in to and take it out of. We do
   not have auto-extending buffers and do not inform anyone else that the
   data has been written. It is really intended for accessing a zip archive
   embedded in an application such that I can write an installer with no
   external files. Creation of archives has not been attempted, although
   parts of the framework are present.

   Based on Unzip ioapi.c version 0.22, May 19th, 2003

   Copyright (C) 2012-2017 Nathan Moinvaziri
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2003 Justin Fletcher
   Copyright (C) 1998-2003 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This file is under the same license as the Unzip tool it is distributed
   with.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#include "ioapi_crypt.h"

#define RAND_HEAD_LEN  12

typedef struct mzstream_crypt_s {
    mzstream        stream;
    uint32_t        keys[3];          /* keys defining the pseudo-random sequence */
    const z_crc_t   *crc_32_tab;
    int16_t         initialized;
    int16_t         error;
    uint8_t         verify1;
    uint8_t         verify2;
    char            *password;
    uint64_t        total_in;
    uint64_t        total_out;
} mzstream_crypt;

#define zdecode(keys,crc_32_tab,c) \
    (mzstream_crypt_update_keys(keys,crc_32_tab, c ^= mzstream_crypt_decrypt_byte(keys)))

#define zencode(keys,crc_32_tab,c,t) \
    (t = mzstream_crypt_decrypt_byte(keys), mzstream_crypt_update_keys(keys,crc_32_tab,c), t^(c))

uint8_t mzstream_crypt_decrypt_byte(uint32_t *keys)
{
    unsigned temp;  /* POTENTIAL BUG:  temp*(temp^1) may overflow in an
                     * unpredictable manner on 16-bit systems; not a problem
                     * with any known compiler so far, though */

    temp = ((uint32_t)(*(keys+2)) & 0xffff) | 2;
    return (uint8_t)(((temp * (temp ^ 1)) >> 8) & 0xff);
}

uint8_t mzstream_crypt_update_keys(uint32_t *keys, const z_crc_t *crc_32_tab, int32_t c)
{
    #define CRC32(c, b) ((*(crc_32_tab+(((uint32_t)(c) ^ (b)) & 0xff))) ^ ((c) >> 8))

    (*(keys+0)) = (uint32_t)CRC32((*(keys+0)), c);
    (*(keys+1)) += (*(keys+0)) & 0xff;
    (*(keys+1)) = (*(keys+1)) * 134775813L + 1;
    {
        register int32_t keyshift = (int32_t)((*(keys + 1)) >> 24);
        (*(keys+2)) = (uint32_t)CRC32((*(keys+2)), keyshift);
    }
    return c;
}

void mzstream_crypt_init_keys(const char *password, uint32_t *keys, const z_crc_t *crc_32_tab)
{
    *(keys+0) = 305419896L;
    *(keys+1) = 591751049L;
    *(keys+2) = 878082192L;
    while (*password != 0)
    {
        mzstream_crypt_update_keys(keys, crc_32_tab, *password);
        password += 1;
    }
}

int32_t ZCALLBACK mzstream_crypt_open(voidpf stream, const char *filename, int mode)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    uint16_t t = 0;
    int16_t i = 0;
    uint8_t header[RAND_HEAD_LEN];
    uint8_t verify1 = 0;
    uint8_t verify2 = 0;

    crypt->total_in = 0;
    crypt->total_out = 0;
    crypt->initialized = 0;

    if (mzstream_is_open(crypt->stream.base) == MZSTREAM_ERR)
        return MZSTREAM_ERR;
    if (crypt->password == NULL)
        return MZSTREAM_ERR;

    crypt->crc_32_tab = get_crc_table();
    if (crypt->crc_32_tab == NULL)
        return MZSTREAM_ERR;

    mzstream_crypt_init_keys(crypt->password, crypt->keys, crypt->crc_32_tab);

    if (mode & MZSTREAM_MODE_WRITE)
    {
        // First generate RAND_HEAD_LEN - 2 random bytes.
        mzstream_os_rand(header, RAND_HEAD_LEN - 2);
        
        // Encrypt random header (last two bytes is high word of crc)
        for (i = 0; i < RAND_HEAD_LEN - 2; i++)
            header[i] = (uint8_t)zencode(crypt->keys, crypt->crc_32_tab, header[i], t);
        
        header[i++] = (uint8_t)zencode(crypt->keys, crypt->crc_32_tab, crypt->verify1, t);
        header[i++] = (uint8_t)zencode(crypt->keys, crypt->crc_32_tab, crypt->verify2, t);

        if (mzstream_write(crypt->stream.base, header, RAND_HEAD_LEN) != RAND_HEAD_LEN)
            return MZSTREAM_ERR;

        crypt->total_out += RAND_HEAD_LEN;
    }
    else if (mode & MZSTREAM_MODE_READ)
    {
        if (mzstream_read(crypt->stream.base, header, RAND_HEAD_LEN) != RAND_HEAD_LEN)
            return MZSTREAM_ERR;

        for (i = 0; i < RAND_HEAD_LEN - 2; i++)
            header[i] = (uint8_t)zdecode(crypt->keys, crypt->crc_32_tab, header[i]);

        crypt->verify1 = (uint8_t)zdecode(crypt->keys, crypt->crc_32_tab, header[i++]);
        crypt->verify2 = (uint8_t)zdecode(crypt->keys, crypt->crc_32_tab, header[i++]);

        crypt->total_in += RAND_HEAD_LEN;
    }

    crypt->initialized = 1;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crypt_is_open(voidpf stream)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    if (crypt->initialized == 0)
        return MZSTREAM_ERR;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crypt_read(voidpf stream, void *buf, uint32_t size)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    uint8_t *buf_ptr = (uint8_t *)buf;
    uint32_t read = 0;
    uint32_t i = 0;

    read = mzstream_read(crypt->stream.base, buf, size);
    for (i = 0; i < read; i++)
        buf_ptr[i] = (uint8_t)zdecode(crypt->keys, crypt->crc_32_tab, buf_ptr[i]);
    crypt->total_in += read;
    return read;
}

int32_t ZCALLBACK mzstream_crypt_write(voidpf stream, const void *buf, uint32_t size)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    uint8_t *buf_ptr = (uint8_t *)buf;
    uint32_t written = 0;
    uint32_t i = 0;
    uint16_t t = 0;
    for (i = 0; i < size; i++)
        buf_ptr[i] = (uint8_t)zencode(crypt->keys, crypt->crc_32_tab, buf_ptr[i], t);
    written = mzstream_write(crypt->stream.base, buf, size);
    if (written > 0)
        crypt->total_out += written;
    if (written != size)
        return MZSTREAM_ERR;
    return written;
}

int64_t ZCALLBACK mzstream_crypt_tell(voidpf stream)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    return mzstream_tell(crypt->stream.base);
}

int32_t ZCALLBACK mzstream_crypt_seek(voidpf stream, uint64_t offset, int origin)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    return mzstream_seek(crypt->stream.base, offset, origin);
}

int32_t ZCALLBACK mzstream_crypt_close(voidpf stream)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    crypt->initialized = 0;
    return MZSTREAM_OK;
}

int32_t ZCALLBACK mzstream_crypt_error(voidpf stream)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    return crypt->error;
}

void mzstream_crypt_set_password(voidpf stream, char *password)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    crypt->password = password;
}

void mzstream_crypt_set_verify(voidpf stream, uint8_t verify1, uint8_t verify2)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    crypt->verify1 = verify1;
    crypt->verify2 = verify2;
}

void mzstream_crypt_get_verify(voidpf stream, uint8_t *verify1, uint8_t *verify2)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    *verify1 = crypt->verify1;
    *verify2 = crypt->verify2;
}

voidpf mzstream_crypt_alloc(void)
{
    mzstream_crypt *crypt = NULL;

    crypt = (mzstream_crypt *)malloc(sizeof(mzstream_crypt));
    if (crypt == NULL)
        return NULL;

    memset(crypt, 0, sizeof(mzstream_crypt));

    crypt->stream.open = mzstream_crypt_open;
    crypt->stream.is_open = mzstream_crypt_is_open;
    crypt->stream.read = mzstream_crypt_read;
    crypt->stream.write = mzstream_crypt_write;
    crypt->stream.tell = mzstream_crypt_tell;
    crypt->stream.seek = mzstream_crypt_seek;
    crypt->stream.close = mzstream_crypt_close;
    crypt->stream.error = mzstream_crypt_error;
    crypt->stream.alloc = mzstream_crypt_alloc;
    crypt->stream.free = mzstream_crypt_free;

    return (voidpf)crypt;
}

void mzstream_crypt_free(voidpf stream)
{
    mzstream_crypt *crypt = (mzstream_crypt *)stream;
    if (crypt != NULL)
        free(crypt);
}