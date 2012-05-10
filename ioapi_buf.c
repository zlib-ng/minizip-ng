/* ioapi_buf.h -- IO base function header for compress/uncompress .zip
   files using zlib + zip or unzip API

   This version of ioapi is designed to buffer IO.

   Based on Unzip ioapi.c version 0.22, May 19th, 2003

   Copyright (C) 1998-2003 Gilles Vollant
             (C) 2003 Justin Fletcher
             (C) 2012 Nathan Moinvaziri

   This file is under the same license as the Unzip tool it is distributed
   with.
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "zlib.h"
#include "ioapi.h"

#include "ioapi_buf.h"

#if defined(_WIN32)
#include <conio.h>
#define printf _cprintf
#endif

#ifdef __GNUC__
#ifndef max
#define max(x,y) ({ \
const typeof(x) _x = (x);	\
const typeof(y) _y = (y);	\
(void) (&_x == &_y);		\
_x > _y ? _x : _y; })
#endif /* __GNUC__ */

#ifndef min
#define min(x,y) ({ \
const typeof(x) _x = (x);	\
const typeof(y) _y = (y);	\
(void) (&_x == &_y);		\
_x < _y ? _x : _y; })
#endif
#endif

voidpf ZCALLBACK fopen_buf_func (opaque, filename, mode)
   voidpf opaque;
   const char* filename;
   int mode;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    return bufio->filefunc.zopen_file(bufio->filefunc.opaque, filename, mode);
}

voidpf ZCALLBACK fopen64_buf_func (opaque, filename, mode)
   voidpf opaque;
   const char* filename;
   int mode;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    return bufio->filefunc64.zopen64_file(bufio->filefunc64.opaque, filename, mode);
}

voidpf ZCALLBACK fopendisk_buf_func (opaque, stream, number_disk, mode)
   voidpf opaque;
   voidpf stream;
   int number_disk;
   int mode;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    return bufio->filefunc.zopendisk_file(bufio->filefunc.opaque, stream, number_disk, mode);
}

voidpf ZCALLBACK fopendisk64_buf_func (opaque, stream, number_disk, mode)
   voidpf opaque;
   voidpf stream;
   int number_disk;
   int mode;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    return bufio->filefunc64.zopendisk64_file(bufio->filefunc64.opaque, stream, number_disk, mode);
}

uLong ZCALLBACK fread_buf_func (opaque, stream, buf, size)
   voidpf opaque;
   voidpf stream;
   void* buf;
   uLong size;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    uInt bytesToRead = 0;
    uInt bufLength = 0;
    uInt bytesToCopy = 0;
    uInt bytesLeftToRead = size;
    uInt bytesRead = -1;

    if (bufio->verbose)
        printf("Buf read [size %ld]\n", size);

    while (bytesLeftToRead > 0)
    {
        if (bufio->readBufferLength == 0)
        {
            bytesToRead = IOBUF_BUFFERSIZE - bufio->readBufferLength;

            if (bufio->filefunc64.zread_file != NULL)
                bytesRead = bufio->filefunc64.zread_file(bufio->filefunc64.opaque, stream, bufio->readBuffer + bufio->readBufferLength, bytesToRead);
            else
                bytesRead = bufio->filefunc.zread_file(bufio->filefunc.opaque, stream, bufio->readBuffer + bufio->readBufferLength, bytesToRead);
            
            if (bufio->verbose)
                printf("Buf filled [bytesToRead %d bytesRead %d len %d]\n", bytesToRead, bytesRead, bufio->readBufferLength + bytesRead);
            
            bufio->readBufferMisses += 1;
            bufio->readBufferLength += bytesRead;
            
            if (bytesRead == 0)
                break;
        }
        
        if (bufio->readBufferLength > 0)
        {
            bytesToCopy = min(bytesLeftToRead, bufio->readBufferLength);

            memcpy((char *)buf + bufLength, bufio->readBuffer, bytesToCopy);
            memcpy(bufio->readBuffer, bufio->readBuffer + bytesToCopy, bufio->readBufferLength - bytesToCopy);

            if (bufio->verbose)
                printf("Buf emptied [bytesToCopy %d bytesLeftToRead %d len %d]\n", bytesToCopy, bytesLeftToRead, bufio->readBufferLength - bytesToCopy);

            bufLength += bytesToCopy;
            bytesLeftToRead -= bytesToCopy;

            bufio->readBufferLength -= bytesToCopy;
            bufio->readBufferHits += 1;
        }
    }

    return size - bytesLeftToRead;
}

long ZCALLBACK fwriteflush_buf_func (opaque, stream)
   voidpf opaque;
   voidpf stream;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    uInt totalBytesWritten = 0;
    uInt bytesToWrite = bufio->writeBufferLength;
    uInt bytesLeftToWrite = bufio->writeBufferLength;
    int bytesWritten = 0;
    
    while (bytesLeftToWrite > 0)
    {
        if (bufio->filefunc64.zwrite_file != NULL)
            bytesWritten = bufio->filefunc64.zwrite_file(bufio->filefunc64.opaque, stream, bufio->writeBuffer + (bytesToWrite - bytesLeftToWrite), bytesLeftToWrite);
        else
            bytesWritten = bufio->filefunc.zwrite_file(bufio->filefunc.opaque, stream, bufio->writeBuffer + (bytesToWrite - bytesLeftToWrite), bytesLeftToWrite);

        bufio->writeBufferMisses += 1;

        if (bufio->verbose)
            printf("Buf write flush [bytesToWrite %d bytesLeftToWrite %d len %d]\n", bytesToWrite, bytesLeftToWrite, bufio->writeBufferLength);

        if (bytesWritten < 0)
            return bytesWritten;

        totalBytesWritten += bytesWritten;
        bytesLeftToWrite -= bytesWritten;
    }
    bufio->writeBufferLength = 0;
    return totalBytesWritten;
}

uLong ZCALLBACK fwrite_buf_func (opaque, stream, buf, size)
   voidpf opaque;
   voidpf stream;
   const void* buf;
   uLong size;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    uInt bytesToWrite = size;
    uInt bytesLeftToWrite = size;
    uInt bytesToCopy = 0;


    if (bufio->verbose)
        printf("Buf write [size %ld len %d]\n", size, bufio->writeBufferLength);

    while (bytesLeftToWrite > 0)
    {
        if (bufio->writeBufferLength == IOBUF_BUFFERSIZE)
        {
            if (fwriteflush_buf_func(opaque, stream) < 0)
                return 0;
        }

        bytesToCopy = min(bytesLeftToWrite, (uInt)(IOBUF_BUFFERSIZE - bufio->writeBufferLength));

        memcpy(bufio->writeBuffer + bufio->writeBufferLength, (char *)buf + (bytesToWrite - bytesLeftToWrite), bytesToCopy);

        if (bufio->verbose)
            printf("Buf write copy [bytesToCopy %d bytesToWrite %d bytesLeftToWrite %d len %d]\n", bytesToCopy, bytesToWrite, bytesLeftToWrite, bufio->writeBufferLength + bytesToCopy);

        bytesLeftToWrite -= bytesToCopy;

        bufio->writeBufferHits += 1;
        bufio->writeBufferLength += bytesToCopy;
    }

    return size - bytesLeftToWrite;
}

long ZCALLBACK ftell_buf_func (opaque, stream)
   voidpf opaque;
   voidpf stream;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    long position = 0;
    position = bufio->filefunc.ztell_file(bufio->filefunc.opaque, stream);
    if (bufio->verbose)
        printf("Buf tell [position %ld readLen %d writeLen %d]\n", position, bufio->readBufferLength, bufio->writeBufferLength);
    if (bufio->readBufferLength > 0)
        position -= bufio->readBufferLength;
    if (bufio->writeBufferLength > 0)
        position += bufio->writeBufferLength;
    return position;
}

ZPOS64_T ZCALLBACK ftell64_buf_func (opaque, stream)
   voidpf opaque;
   voidpf stream;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    ZPOS64_T position = 0;
    position = bufio->filefunc64.ztell64_file(bufio->filefunc64.opaque, stream);
    if (bufio->verbose)
        printf("Buf tell64 [position %llu readLen %d writeLen %d]\n", position, bufio->readBufferLength, bufio->writeBufferLength);
    if (bufio->readBufferLength > 0)
        position -= bufio->readBufferLength;
    if (bufio->writeBufferLength > 0)
        position += bufio->writeBufferLength;
    return position;
}

long ZCALLBACK fseek_buf_func (opaque, stream, offset, origin)
   voidpf opaque;
   voidpf stream;
   uLong offset;
   int origin;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    if (bufio->verbose)
    {
        char *origins = "end";
        if (origin == ZLIB_FILEFUNC_SEEK_CUR) 
            origins = "cur"; 
        else if (origin == ZLIB_FILEFUNC_SEEK_SET) 
            origins = "set";
        printf("Buf seek64 [offset %ld origin %s]\n", offset, origins);
    }
    if (bufio->writeBufferLength > 0)
    {
        if (fwriteflush_buf_func(opaque, stream) < 0)
            return -1;
    }
    if (bufio->readBufferLength > 0)
    {
        if (origin == ZLIB_FILEFUNC_SEEK_CUR)
        {
            if (offset <= bufio->readBufferLength)
            {
                bufio->readBufferLength -= offset;
                memcpy(bufio->readBuffer, bufio->readBuffer + offset, bufio->readBufferLength);
                return 0;
            }
            offset -= bufio->readBufferLength;
        }
        bufio->readBufferLength = 0;
    }
    return bufio->filefunc.zseek_file(bufio->filefunc.opaque, stream, offset, origin);
}

long ZCALLBACK fseek64_buf_func (opaque, stream, offset, origin)
   voidpf opaque;
   voidpf stream;
   ZPOS64_T offset;
   int origin;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    if (bufio->verbose)
    {
        char *origins = "end";
        if (origin == ZLIB_FILEFUNC_SEEK_CUR) 
            origins = "cur"; 
        else if (origin == ZLIB_FILEFUNC_SEEK_SET) 
            origins = "set";
        printf("Buf seek64 [offset %llu origin %s]\n", offset, origins);
    }
    if (bufio->writeBufferLength > 0)
    {
        if (fwriteflush_buf_func(opaque, stream) < 0)
            return -1;
    }
    if (bufio->readBufferLength > 0)
    {
        if (origin == ZLIB_FILEFUNC_SEEK_CUR)
        {
            if (offset <= bufio->readBufferLength)
            {
                bufio->readBufferLength -= (uLong)offset;
                memcpy(bufio->readBuffer, bufio->readBuffer + (uLong)offset, bufio->readBufferLength);
                return 0;
            }
            offset -= bufio->readBufferLength;
        }
        bufio->readBufferLength = 0;
    }
    return bufio->filefunc64.zseek64_file(bufio->filefunc64.opaque, stream, offset, origin);
}

int ZCALLBACK fclose_buf_func (opaque, stream)
   voidpf opaque;
   voidpf stream;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    if (bufio->writeBufferLength > 0)
        fwriteflush_buf_func(opaque, stream);
    if (bufio->verbose)
    {
        if (bufio->readBufferHits + bufio->readBufferMisses > 0)
            printf("Buf read efficency %.02f%%\n", (bufio->readBufferHits / ((float)bufio->readBufferHits + bufio->readBufferMisses)) * 100);
        if (bufio->writeBufferHits + bufio->writeBufferMisses > 0)
            printf("Buf write efficency %.02f%%\n", (bufio->writeBufferHits / ((float)bufio->writeBufferHits + bufio->writeBufferMisses)) * 100);
    }
    if (bufio->filefunc64.zclose_file != NULL)
        return bufio->filefunc64.zclose_file(bufio->filefunc64.opaque, stream);
    return bufio->filefunc.zclose_file(bufio->filefunc.opaque, stream);
}

int ZCALLBACK ferror_buf_func (opaque, stream)
   voidpf opaque;
   voidpf stream;
{
    ourbuffer_t *bufio = (ourbuffer_t *)opaque;
    if (bufio->filefunc64.zerror_file != NULL)
        return bufio->filefunc64.zerror_file(bufio->filefunc64.opaque, stream);
    return bufio->filefunc.zerror_file(bufio->filefunc.opaque, stream);
}


void fill_buffer_filefunc (pzlib_filefunc_def, ourbuf)
  zlib_filefunc_def* pzlib_filefunc_def;
  ourbuffer_t *ourbuf;
{
    pzlib_filefunc_def->zopen_file = fopen_buf_func;
    pzlib_filefunc_def->zopendisk_file = fopendisk_buf_func;
    pzlib_filefunc_def->zread_file = fread_buf_func;
    pzlib_filefunc_def->zwrite_file = fwrite_buf_func;
    pzlib_filefunc_def->ztell_file = ftell_buf_func;
    pzlib_filefunc_def->zseek_file = fseek_buf_func;
    pzlib_filefunc_def->zclose_file = fclose_buf_func;
    pzlib_filefunc_def->zerror_file = ferror_buf_func;
    pzlib_filefunc_def->opaque = ourbuf;
    //ourbuf->verbose = 1;
}

void fill_buffer_filefunc64 (pzlib_filefunc_def, ourbuf)
  zlib_filefunc64_def* pzlib_filefunc_def;
  ourbuffer_t *ourbuf;
{
    pzlib_filefunc_def->zopen64_file = fopen64_buf_func;
    pzlib_filefunc_def->zopendisk64_file = fopendisk64_buf_func;
    pzlib_filefunc_def->zread_file = fread_buf_func;
    pzlib_filefunc_def->zwrite_file = fwrite_buf_func;
    pzlib_filefunc_def->ztell64_file = ftell64_buf_func;
    pzlib_filefunc_def->zseek64_file = fseek64_buf_func;
    pzlib_filefunc_def->zclose_file = fclose_buf_func;
    pzlib_filefunc_def->zerror_file = ferror_buf_func;
    pzlib_filefunc_def->opaque = ourbuf;
    //ourbuf->verbose = 1;
}
