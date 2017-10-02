/* zip.c -- IO on .zip files using zlib
   Version 1.2.0, September 16th, 2017
   part of the MiniZip project

   Copyright (C) 2010-2017 Nathan Moinvaziri
     Modifications for AES, PKWARE disk spanning
     https://github.com/nmoinvaz/minizip
   Copyright (C) 2009-2010 Mathias Svensson
     Modifications for Zip64 support
     http://result42.com
   Copyright (C) 1998-2010 Gilles Vollant
     http://www.winimage.com/zLibDll/minizip.html

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "zlib.h"
#include "zip.h"

#ifdef HAVE_APPLE_COMPRESSION
#  include <compression.h>
#endif

#include "mzstrm.h"
#include "mzstrm_zlib.h"
#ifdef HAVE_AES
#  define AES_METHOD          (99)
#  define AES_VERSION         (0x0001)
#  define AES_ENCRYPTIONMODE  (0x03)
#  include "mzstrm_aes.h"
#endif
#ifndef NOCRYPT
#  include "mzstrm_crypt.h"
#endif

#define SIZEDATA_INDATABLOCK        (4096-(4*4))

#define DISKHEADERMAGIC             (0x08074b50)
#define LOCALHEADERMAGIC            (0x04034b50)
#define CENTRALHEADERMAGIC          (0x02014b50)
#define ENDHEADERMAGIC              (0x06054b50)
#define ZIP64ENDHEADERMAGIC         (0x06064b50)
#define ZIP64ENDLOCHEADERMAGIC      (0x07064b50)
#define DATADESCRIPTORMAGIC         (0x08074b50)

#define FLAG_LOCALHEADER_OFFSET     (0x06)
#define CRC_LOCALHEADER_OFFSET      (0x0e)

#define SIZECENTRALHEADER           (0x2e) /* 46 */
#define SIZECENTRALHEADERLOCATOR    (0x14) /* 20 */
#define SIZECENTRALDIRITEM          (0x2e)
#define SIZEZIPLOCALHEADER          (0x1e)

#ifndef BUFREADCOMMENT
#  define BUFREADCOMMENT            (0x400)
#endif
#ifndef VERSIONMADEBY
#  define VERSIONMADEBY             (0x0) /* platform dependent */
#endif

#ifndef Z_BUFSIZE
#  define Z_BUFSIZE                 (UINT16_MAX)
#endif

#ifndef ALLOC
#  define ALLOC(size) (malloc(size))
#endif
#ifndef TRYFREE
#  define TRYFREE(p) {if (p) free(p);}
#endif

/* NOT sure that this work on ALL platform */
#define MAKEULONG64(a, b) ((uint64_t)(((unsigned long)(a)) | ((uint64_t)((unsigned long)(b))) << 32))

const char zip_copyright[] = " zip 1.01 Copyright 1998-2004 Gilles Vollant - http://www.winimage.com/zLibDll";

typedef struct linkedlist_datablock_internal_s
{
    struct linkedlist_datablock_internal_s *next_datablock;
    uint32_t    avail_in_this_block;
    uint32_t    filled_in_this_block;
    uint32_t    unused; /* for future use and alignment */
    uint8_t     data[SIZEDATA_INDATABLOCK];
} linkedlist_datablock_internal;

typedef struct linkedlist_data_s
{
    linkedlist_datablock_internal *first_block;
    linkedlist_datablock_internal *last_block;
} linkedlist_data;

typedef struct
{
    void     *compress_stream;
    void     *crc32_stream;
    void     *crypt_stream;
    int      stream_initialised;    /* 1 is stream is initialized */
    uint64_t pos_local_header;      /* offset of the local header of the file currently writing */
    char     *central_header;       /* central header data for the current file */
    uint16_t size_centralextra;
    uint16_t size_centralheader;    /* size of the central header for cur file */
    uint16_t size_centralextrafree; /* Extra bytes allocated to the central header but that are not used */
    uint16_t size_comment;
    uint16_t flag;                  /* flag of the file currently writing */

    uint16_t method;                /* compression method written to file.*/
    uint16_t compression_method;    /* compression method to use */
    int      raw;                   /* 1 for directly writing raw data */
    uint32_t dos_date;
    uint32_t crc32;
    int      zip64;                 /* add ZIP64 extended information in the extra field */
    uint32_t number_disk;           /* number of current disk used for spanning ZIP */
    uint64_t total_compressed;
    uint64_t total_uncompressed;
} curfile64_info;

typedef struct
{
    voidpf stream;                  /* io structure of the zipfile */
    voidpf stream_cd;               /* io structure of the zipfile with the central dir */
    linkedlist_data central_dir;    /* datablock with central dir in construction*/
    int in_opened_file_inzip;       /* 1 if a file in the zip is currently writ.*/
    int append;                     /* append mode */
    curfile64_info ci;              /* info on the file currently writing */

    uint64_t add_position_when_writting_offset;
    uint64_t number_entry;
    uint64_t disk_size;             /* size of each disk */
    uint32_t number_disk;           /* number of the current disk, used for spanning ZIP */
    uint32_t number_disk_with_CD;   /* number the the disk with central dir, used for spanning ZIP */
#ifndef NO_ADDFILEINEXISTINGZIP
    char *globalcomment;
#endif
} zip64_internal;

/* Allocate a new data block */
static linkedlist_datablock_internal *allocate_new_datablock(void)
{
    linkedlist_datablock_internal *ldi = NULL;

    ldi = (linkedlist_datablock_internal*)ALLOC(sizeof(linkedlist_datablock_internal));

    if (ldi != NULL)
    {
        ldi->next_datablock = NULL;
        ldi->filled_in_this_block = 0;
        ldi->avail_in_this_block = SIZEDATA_INDATABLOCK;
    }
    return ldi;
}

/* Free data block in linked list */
static void free_datablock(linkedlist_datablock_internal *ldi)
{
    while (ldi != NULL)
    {
        linkedlist_datablock_internal *ldinext = ldi->next_datablock;
        TRYFREE(ldi);
        ldi = ldinext;
    }
}

/* Initialize linked list */
static void init_linkedlist(linkedlist_data *ll)
{
    ll->first_block = ll->last_block = NULL;
}

/* Free entire linked list and all data blocks */
static void free_linkedlist(linkedlist_data *ll)
{
    free_datablock(ll->first_block);
    ll->first_block = ll->last_block = NULL;
}

/* Add data to linked list data block */
static int add_data_in_datablock(linkedlist_data *ll, const void *buf, uint32_t len)
{
    linkedlist_datablock_internal *ldi = NULL;
    const unsigned char *from_copy = NULL;

    if (ll == NULL)
        return ZIP_INTERNALERROR;

    if (ll->last_block == NULL)
    {
        ll->first_block = ll->last_block = allocate_new_datablock();
        if (ll->first_block == NULL)
            return ZIP_INTERNALERROR;
    }

    ldi = ll->last_block;
    from_copy = (unsigned char*)buf;

    while (len > 0)
    {
        uint32_t copy_this = 0;
        uint32_t i = 0;
        unsigned char *to_copy = NULL;

        if (ldi->avail_in_this_block == 0)
        {
            ldi->next_datablock = allocate_new_datablock();
            if (ldi->next_datablock == NULL)
                return ZIP_INTERNALERROR;
            ldi = ldi->next_datablock ;
            ll->last_block = ldi;
        }

        if (ldi->avail_in_this_block < len)
            copy_this = ldi->avail_in_this_block;
        else
            copy_this = len;

        to_copy = &(ldi->data[ldi->filled_in_this_block]);

        for (i = 0; i < copy_this; i++)
            *(to_copy+i) = *(from_copy+i);

        ldi->filled_in_this_block += copy_this;
        ldi->avail_in_this_block -= copy_this;
        from_copy += copy_this;
        len -= copy_this;
    }
    return ZIP_OK;
}

/* Inputs a long in LSB order to the given file: nbByte == 1, 2 ,4 or 8 (byte, short or long, uint64_t) */
static int zipWriteValue(voidpf stream, uint64_t x, uint32_t len)
{
    unsigned char buf[8];
    uint32_t n = 0;

    for (n = 0; n < len; n++)
    {
        buf[n] = (unsigned char)(x & 0xff);
        x >>= 8;
    }

    if (x != 0)
    {
        /* Data overflow - hack for ZIP64 (X Roche) */
        for (n = 0; n < len; n++)
        {
            buf[n] = 0xff;
        }
    }

    if (mz_stream_write(stream, buf, len) != len)
        return ZIP_ERRNO;

    return ZIP_OK;
}

static void zipWriteValueToMemory(void* dest, uint64_t x, uint32_t len)
{
    unsigned char *buf = (unsigned char*)dest;
    uint32_t n = 0;

    for (n = 0; n < len; n++)
    {
        buf[n] = (unsigned char)(x & 0xff);
        x >>= 8;
    }

    if (x != 0)
    {
       /* data overflow - hack for ZIP64 */
       for (n = 0; n < len; n++)
       {
          buf[n] = 0xff;
       }
    }
}

static void zipWriteValueToMemoryAndMove(unsigned char **dest_ptr, uint64_t x, uint32_t len)
{
    zipWriteValueToMemory(*dest_ptr, x, len);
    *dest_ptr += len;
}

/* Gets the amount of bytes left to write to the current disk for spanning archives */
static void zipGetDiskSizeAvailable(zipFile file, uint64_t *size_available)
{
    zip64_internal *zi = NULL;
    uint64_t current_disk_size = 0;

    zi = (zip64_internal*)file;
    mz_stream_seek(zi->stream, 0, MZ_STREAM_SEEK_END);
    current_disk_size = mz_stream_tell(zi->stream);
    *size_available = zi->disk_size - current_disk_size;
}

/* Goes to a specific disk number for spanning archives */
static int zipGoToSpecificDisk(zipFile file, uint32_t number_disk, int open_existing)
{
    zip64_internal *zi = NULL;
    int err = ZIP_OK;

    zi = (zip64_internal*)file;
    if (zi->disk_size == 0)
        return err;

    if ((zi->stream != NULL) && (zi->stream != zi->stream_cd))
        mz_stream_close(zi->stream);
    /*
    zi->filestream = ZOPENDISK64(zi->stream_with_CD, number_disk, (open_existing == 1) ?
            (MZ_MODE_READ | MZ_MODE_WRITE | MZ_MODE_EXISTING) :
            (MZ_MODE_READ | MZ_MODE_WRITE | MZ_MODE_CREATE));
    */
    if (zi->stream == NULL)
        err = ZIP_ERRNO;

    return err;
}

/* Goes to the first disk in a spanned archive */
static int zipGoToFirstDisk(zipFile file)
{
    zip64_internal *zi = NULL;
    uint32_t number_disk_next = 0;
    int err = ZIP_OK;

    zi = (zip64_internal*)file;

    if (zi->disk_size == 0)
        return err;
    number_disk_next = 0;
    if (zi->number_disk_with_CD > 0)
        number_disk_next = zi->number_disk_with_CD - 1;
    err = zipGoToSpecificDisk(file, number_disk_next, (zi->append == APPEND_STATUS_ADDINZIP));
    if ((err == ZIP_ERRNO) && (zi->append == APPEND_STATUS_ADDINZIP))
        err = zipGoToSpecificDisk(file, number_disk_next, 0);
    if (err == ZIP_OK)
        zi->number_disk = number_disk_next;

    mz_stream_seek(zi->stream, 0, MZ_STREAM_SEEK_END);
    return err;
}

/* Goes to the next disk in a spanned archive */
static int zipGoToNextDisk(zipFile file)
{
    zip64_internal *zi = NULL;
    uint64_t size_available_in_disk = 0;
    uint32_t number_disk_next = 0;
    int err = ZIP_OK;

    zi = (zip64_internal*)file;
    if (zi->disk_size == 0)
        return err;

    number_disk_next = zi->number_disk + 1;

    do
    {
        err = zipGoToSpecificDisk(file, number_disk_next, (zi->append == APPEND_STATUS_ADDINZIP));
        if ((err == ZIP_ERRNO) && (zi->append == APPEND_STATUS_ADDINZIP))
            err = zipGoToSpecificDisk(file, number_disk_next, 0);
        if (err != ZIP_OK)
            break;
        zipGetDiskSizeAvailable(file, &size_available_in_disk);
        zi->number_disk = number_disk_next;
        zi->number_disk_with_CD = zi->number_disk + 1;

        number_disk_next += 1;
    }
    while (size_available_in_disk <= 0);

    return err;
}

/* Locate the Central directory of a zipfile (at the end, just before the global comment) */
static uint64_t zipSearchCentralDir(voidpf stream)
{
    unsigned char *buf = NULL;
    uint64_t file_size = 0;
    uint64_t back_read = 4;
    uint64_t max_back = UINT16_MAX; /* maximum size of global comment */
    uint64_t pos_found = 0;
    uint32_t read_size = 0;
    uint64_t read_pos = 0;
    uint32_t i = 0;

    buf = (unsigned char*)ALLOC(BUFREADCOMMENT+4);
    if (buf == NULL)
        return 0;

    if (mz_stream_seek(stream, 0, MZ_STREAM_SEEK_END) != 0)
    {
        TRYFREE(buf);
        return 0;
    }

    file_size = mz_stream_tell(stream);

    if (max_back > file_size)
        max_back = file_size;

    while (back_read < max_back)
    {
        if (back_read + BUFREADCOMMENT > max_back)
            back_read = max_back;
        else
            back_read += BUFREADCOMMENT;

        read_pos = file_size-back_read;
        read_size = ((BUFREADCOMMENT+4) < (file_size - read_pos)) ?
                     (BUFREADCOMMENT+4) : (uint32_t)(file_size - read_pos);

        if (mz_stream_seek(stream, read_pos, MZ_STREAM_SEEK_SET) == MZ_STREAM_ERR)
            break;
        if (mz_stream_read(stream, buf, read_size) != read_size)
            break;

        for (i = read_size-3; (i--) > 0;)
            if ((*(buf+i)) == (ENDHEADERMAGIC & 0xff) &&
                (*(buf+i+1)) == (ENDHEADERMAGIC >> 8 & 0xff) &&
                (*(buf+i+2)) == (ENDHEADERMAGIC >> 16 & 0xff) &&
                (*(buf+i+3)) == (ENDHEADERMAGIC >> 24 & 0xff))
            {
                pos_found = read_pos+i;
                break;
            }

        if (pos_found != 0)
            break;
    }
    TRYFREE(buf);
    return pos_found;
}

/* Locate the Central directory 64 of a zipfile (at the end, just before the global comment) */
static uint64_t zipSearchCentralDir64(voidpf stream, const uint64_t endcentraloffset)
{
    uint64_t offset = 0;
    uint32_t value32 = 0;

    /* Zip64 end of central directory locator */
    if (mz_stream_seek(stream, endcentraloffset - SIZECENTRALHEADERLOCATOR, MZ_STREAM_SEEK_SET) != 0)
        return 0;

    /* Read locator signature */
    if (mz_stream_read_uint32(stream, &value32) != ZIP_OK)
        return 0;
    if (value32 != ZIP64ENDLOCHEADERMAGIC)
        return 0;
    /* Number of the disk with the start of the zip64 end of  central directory */
    if (mz_stream_read_uint32(stream, &value32) != ZIP_OK)
        return 0;
    /* Relative offset of the zip64 end of central directory record */
    if (mz_stream_read_uint64(stream, &offset) != ZIP_OK)
        return 0;
    /* Total number of disks */
    if (mz_stream_read_uint32(stream, &value32) != ZIP_OK)
        return 0;
    /* Goto end of central directory record */
    if (mz_stream_seek(stream, offset, MZ_STREAM_SEEK_SET) != 0)
        return 0;
    /* The signature */
    if (mz_stream_read_uint32(stream, &value32) != ZIP_OK)
        return 0;
    if (value32 != ZIP64ENDHEADERMAGIC)
        return 0;

    return offset;
}

extern zipFile ZEXPORT zipOpen4(const char *path, int append, uint64_t disk_size, const char **globalcomment, voidpf stream)
{
    zip64_internal ziinit;
    zip64_internal *zi = NULL;
#ifndef NO_ADDFILEINEXISTINGZIP
    uint64_t byte_before_the_zipfile = 0;   /* byte before the zipfile, (>0 for sfx)*/
    uint64_t size_central_dir = 0;          /* size of the central directory  */
    uint64_t offset_central_dir = 0;        /* offset of start of central directory */
    uint64_t number_entry_CD = 0;           /* total number of entries in the central dir */
    uint64_t number_entry = 0;
    uint64_t central_pos = 0;
    uint64_t size_central_dir_to_read = 0;
    uint16_t value16 = 0;
    uint32_t value32 = 0;
    uint16_t size_comment = 0;
    size_t buf_size = SIZEDATA_INDATABLOCK;
    void *buf_read = NULL;
#endif
    int err = ZIP_OK;
    int mode = 0;

    if (append == APPEND_STATUS_CREATE)
        mode = (MZ_STREAM_MODE_READ | MZ_STREAM_MODE_WRITE | MZ_STREAM_MODE_CREATE);
    else
        mode = (MZ_STREAM_MODE_READ | MZ_STREAM_MODE_WRITE | MZ_STREAM_MODE_EXISTING);

    if (mz_stream_open(stream, path, mode) == MZ_STREAM_ERR)
        return NULL;

    if (append == APPEND_STATUS_CREATEAFTER)
    {
        /* Don't support spanning ZIP with APPEND_STATUS_CREATEAFTER */
        if (disk_size > 0)
            return NULL;
        if (mz_stream_seek(stream, 0, SEEK_END) == MZ_STREAM_ERR)
            return NULL;
    }

    ziinit.stream = stream;
    ziinit.stream_cd = stream;
    ziinit.append = append;
    ziinit.number_disk = 0;
    ziinit.number_disk_with_CD = 0;
    ziinit.disk_size = disk_size;
    ziinit.in_opened_file_inzip = 0;
    ziinit.ci.stream_initialised = 0;
    ziinit.number_entry = 0;
    ziinit.add_position_when_writting_offset = 0;

    init_linkedlist(&(ziinit.central_dir));

    zi = (zip64_internal*)ALLOC(sizeof(zip64_internal));
    if (zi == NULL)
    {
        mz_stream_close(ziinit.stream);
        return NULL;
    }

#ifndef NO_ADDFILEINEXISTINGZIP
    /* Add file in a zipfile */
    ziinit.globalcomment = NULL;
    if (append == APPEND_STATUS_ADDINZIP)
    {
        /* Read and Cache Central Directory Records */
        central_pos = zipSearchCentralDir(ziinit.stream);
        /* Disable to allow appending to empty ZIP archive (must be standard zip, not zip64)
            if (central_pos == 0)
                err = ZIP_ERRNO;
        */

        if (err == ZIP_OK)
        {
            /* Read end of central directory info */
            if (mz_stream_seek(ziinit.stream, central_pos,MZ_STREAM_SEEK_SET) != 0)
                err = ZIP_ERRNO;

            /* The signature, already checked */
            if (mz_stream_read_uint32(ziinit.stream, &value32) != ZIP_OK)
                err = ZIP_ERRNO;
            /* Number of this disk */
            if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                err = ZIP_ERRNO;
            ziinit.number_disk = value16;
            /* Number of the disk with the start of the central directory */
            if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                err = ZIP_ERRNO;
            ziinit.number_disk_with_CD = value16;
            /* Total number of entries in the central dir on this disk */
            number_entry = 0;
            if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                err = ZIP_ERRNO;
            else
                number_entry = value16;
            /* Total number of entries in the central dir */
            number_entry_CD = 0;
            if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                err = ZIP_ERRNO;
            else
                number_entry_CD = value16;
            if (number_entry_CD!=number_entry)
                err = ZIP_BADZIPFILE;
            /* Size of the central directory */
            size_central_dir = 0;
            if (mz_stream_read_uint32(ziinit.stream, &value32) != ZIP_OK)
                err = ZIP_ERRNO;
            else
                size_central_dir = value32;
            /* Offset of start of central directory with respect to the starting disk number */
            offset_central_dir = 0;
            if (mz_stream_read_uint32(ziinit.stream, &value32) != ZIP_OK)
                err = ZIP_ERRNO;
            else
                offset_central_dir = value32;
            /* Zipfile global comment length */
            if (mz_stream_read_uint16(ziinit.stream, &size_comment) != ZIP_OK)
                err = ZIP_ERRNO;

            if ((err == ZIP_OK) && ((number_entry_CD == UINT16_MAX) || (offset_central_dir == UINT32_MAX)))
            {
                /* Format should be Zip64, as the central directory or file size is too large */
                central_pos = zipSearchCentralDir64(ziinit.stream, central_pos);

                if (central_pos)
                {
                    uint64_t sizeEndOfCentralDirectory;

                    if (mz_stream_seek(ziinit.stream, central_pos, MZ_STREAM_SEEK_SET) != 0)
                        err = ZIP_ERRNO;

                    /* The signature, already checked */
                    if (mz_stream_read_uint32(ziinit.stream, &value32) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Size of zip64 end of central directory record */
                    if (mz_stream_read_uint64(ziinit.stream, &sizeEndOfCentralDirectory) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Version made by */
                    if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Version needed to extract */
                    if (mz_stream_read_uint16(ziinit.stream, &value16) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Number of this disk */
                    if (mz_stream_read_uint32(ziinit.stream, &ziinit.number_disk) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Number of the disk with the start of the central directory */
                    if (mz_stream_read_uint32(ziinit.stream, &ziinit.number_disk_with_CD) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Total number of entries in the central directory on this disk */
                    if (mz_stream_read_uint64(ziinit.stream, &number_entry) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Total number of entries in the central directory */
                    if (mz_stream_read_uint64(ziinit.stream, &number_entry_CD) != ZIP_OK)
                        err = ZIP_ERRNO;
                    if (number_entry_CD!=number_entry)
                        err = ZIP_BADZIPFILE;
                    /* Size of the central directory */
                    if (mz_stream_read_uint64(ziinit.stream, &size_central_dir) != ZIP_OK)
                        err = ZIP_ERRNO;
                    /* Offset of start of central directory with respect to the starting disk number */
                    if (mz_stream_read_uint64(ziinit.stream, &offset_central_dir) != ZIP_OK)
                        err = ZIP_ERRNO;
                }
                else
                    err = ZIP_BADZIPFILE;
             }
        }

        if ((err == ZIP_OK) && (central_pos < offset_central_dir + size_central_dir))
            err = ZIP_BADZIPFILE;

        if ((err == ZIP_OK) && (size_comment > 0))
        {
            ziinit.globalcomment = (char*)ALLOC(size_comment+1);
            if (ziinit.globalcomment)
            {
                if (mz_stream_read(ziinit.stream, ziinit.globalcomment, size_comment) != size_comment)
                    err = ZIP_ERRNO;
                else
                    ziinit.globalcomment[size_comment] = 0;
            }
        }

        if (err != ZIP_OK)
        {
            mz_stream_close(ziinit.stream);
            TRYFREE(ziinit.globalcomment);
            TRYFREE(zi);
            return NULL;
        }

        byte_before_the_zipfile = central_pos - (offset_central_dir+size_central_dir);
        ziinit.add_position_when_writting_offset = byte_before_the_zipfile;

        /* Store central directory in memory */
        size_central_dir_to_read = size_central_dir;
        buf_size = SIZEDATA_INDATABLOCK;
        buf_read = (void*)ALLOC(buf_size);

        if (mz_stream_seek(ziinit.stream,
                offset_central_dir + byte_before_the_zipfile, MZ_STREAM_SEEK_SET) == MZ_STREAM_ERR)
            err = ZIP_ERRNO;

        while ((size_central_dir_to_read > 0) && (err == ZIP_OK))
        {
            uint64_t read_this = SIZEDATA_INDATABLOCK;

            if (read_this > size_central_dir_to_read)
                read_this = size_central_dir_to_read;

            if (mz_stream_read(ziinit.stream, buf_read, (uint32_t)read_this) != read_this)
                err = ZIP_ERRNO;

            if (err == ZIP_OK)
                err = add_data_in_datablock(&ziinit.central_dir, buf_read, (uint32_t)read_this);

            size_central_dir_to_read -= read_this;
        }
        TRYFREE(buf_read);

        ziinit.number_entry = number_entry_CD;

        if (mz_stream_seek(ziinit.stream,
                offset_central_dir+byte_before_the_zipfile, MZ_STREAM_SEEK_SET) == MZ_STREAM_ERR)
            err = ZIP_ERRNO;
    }

    if (globalcomment)
        *globalcomment = ziinit.globalcomment;
#endif

    if (err != ZIP_OK)
    {
#ifndef NO_ADDFILEINEXISTINGZIP
        TRYFREE(ziinit.globalcomment);
#endif
        TRYFREE(zi);
        return NULL;
    }

    *zi = ziinit;
    zipGoToFirstDisk((zipFile)zi);
    return(zipFile)zi;
}

extern zipFile ZEXPORT zipOpen(const char *path, int append, voidpf stream)
{
    return zipOpen4(path, append, 0, NULL, stream);
}

extern zipFile ZEXPORT zipOpen2(const char *path, int append, const char **globalcomment, voidpf stream)
{
    return zipOpen4(path, append, 0, globalcomment, stream);
}

extern zipFile ZEXPORT zipOpen3(const char *path, int append, uint64_t disk_size, const char **globalcomment, voidpf stream)
{
    return zipOpen4(path, append, disk_size, globalcomment, stream);
}

extern int ZEXPORT zipOpenNewFileInZip4_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits, int memLevel,
    int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base, int zip64)
{
    zip64_internal *zi = NULL;
    uint64_t size_available = 0;
    uint64_t size_needed = 0;
    uint16_t size_filename = 0;
    uint16_t size_comment = 0;
    uint16_t i = 0;
    unsigned char *central_dir = NULL;
    int err = ZIP_OK;

#ifdef NOCRYPT
    if (password != NULL)
        return ZIP_PARAMERROR;
#endif

    if (file == NULL)
        return ZIP_PARAMERROR;

    if ((method != 0) &&
#ifdef HAVE_BZIP2
        (method != Z_BZIP2ED) &&
#endif
        (method != Z_DEFLATED))
        return ZIP_PARAMERROR;

    zi = (zip64_internal*)file;

    if (zi->in_opened_file_inzip == 1)
    {
        err = zipCloseFileInZip (file);
        if (err != ZIP_OK)
            return err;
    }

    if (filename == NULL)
        filename = "-";
    if (comment != NULL)
        size_comment = (uint16_t)strlen(comment);

    size_filename = (uint16_t)strlen(filename);

    if (zipfi == NULL)
        zi->ci.dos_date = 0;
    else
    {
        if (zipfi->dos_date != 0)
            zi->ci.dos_date = zipfi->dos_date;
    }

    zi->ci.method = method;
    zi->ci.compression_method = method;
    zi->ci.raw = raw;
    zi->ci.flag = flag_base | 8;
    if ((level == 8) || (level == 9))
        zi->ci.flag |= 2;
    if (level == 2)
        zi->ci.flag |= 4;
    if (level == 1)
        zi->ci.flag |= 6;

    if (password != NULL)
    {
        zi->ci.flag |= 1;
#ifdef HAVE_AES
        zi->ci.method = AES_METHOD;
#endif
    }
    else
    {
        zi->ci.flag &= ~1;
    }

    if (zi->disk_size > 0)
    {
        if ((zi->number_disk == 0) && (zi->number_entry == 0))
            err = zipWriteValue(zi->stream, (uint32_t)DISKHEADERMAGIC, 4);

        /* Make sure enough space available on current disk for local header */
        zipGetDiskSizeAvailable((zipFile)zi, &size_available);
        size_needed = 30 + size_filename + size_extrafield_local;
#ifdef HAVE_AES
        if (zi->ci.method == AES_METHOD)
            size_needed += 11;
#endif
        if (size_available < size_needed)
            zipGoToNextDisk((zipFile)zi);
    }

    zi->ci.zip64 = zip64;

    zi->ci.pos_local_header = mz_stream_tell(zi->stream);
    if (zi->ci.pos_local_header >= UINT32_MAX)
        zi->ci.zip64 = 1;

    zi->ci.size_comment = size_comment;
    zi->ci.size_centralheader = SIZECENTRALHEADER + size_filename + size_extrafield_global;
    zi->ci.size_centralextra = size_extrafield_global;
    zi->ci.size_centralextrafree = 32; /* Extra space reserved for ZIP64 extra info */
#ifdef HAVE_AES
    if (zi->ci.method == AES_METHOD)
        zi->ci.size_centralextrafree += 11; /* Extra space reserved for AES extra info */
#endif
    zi->ci.central_header = (char*)ALLOC((uint32_t)zi->ci.size_centralheader + zi->ci.size_centralextrafree + size_comment);
    zi->ci.number_disk = zi->number_disk;

    /* Write central directory header */
    central_dir = (unsigned char*)zi->ci.central_header;
    zipWriteValueToMemoryAndMove(&central_dir, (uint32_t)CENTRALHEADERMAGIC, 4);
    zipWriteValueToMemoryAndMove(&central_dir, version_madeby, 2);
    if (zi->ci.zip64)
        zipWriteValueToMemoryAndMove(&central_dir, (uint16_t)45, 2);
    else
        zipWriteValueToMemoryAndMove(&central_dir, (uint16_t)20, 2);
    zipWriteValueToMemoryAndMove(&central_dir, zi->ci.flag, 2);
    zipWriteValueToMemoryAndMove(&central_dir, zi->ci.method, 2);
    zipWriteValueToMemoryAndMove(&central_dir, zi->ci.dos_date, 4);
    zipWriteValueToMemoryAndMove(&central_dir, (uint32_t)0, 4); /*crc*/
    zipWriteValueToMemoryAndMove(&central_dir, (uint32_t)0, 4); /*compr size*/
    zipWriteValueToMemoryAndMove(&central_dir, (uint32_t)0, 4); /*uncompr size*/
    zipWriteValueToMemoryAndMove(&central_dir, size_filename, 2);
    zipWriteValueToMemoryAndMove(&central_dir, size_extrafield_global, 2);
    zipWriteValueToMemoryAndMove(&central_dir, size_comment, 2);
    zipWriteValueToMemoryAndMove(&central_dir, (uint16_t)zi->ci.number_disk, 2); /*disk nm start*/

    if (zipfi == NULL)
        zipWriteValueToMemoryAndMove(&central_dir, (uint16_t)0, 2);
    else
        zipWriteValueToMemoryAndMove(&central_dir, zipfi->internal_fa, 2);
    if (zipfi == NULL)
        zipWriteValueToMemoryAndMove(&central_dir, (uint32_t)0, 4);
    else
        zipWriteValueToMemoryAndMove(&central_dir, zipfi->external_fa, 4);
    if (zi->ci.pos_local_header >= UINT32_MAX)
        zipWriteValueToMemoryAndMove(&central_dir, UINT32_MAX, 4);
    else
        zipWriteValueToMemoryAndMove(&central_dir,
            (uint32_t)(zi->ci.pos_local_header - zi->add_position_when_writting_offset), 4);

    for (i = 0; i < size_filename; i++)
        zi->ci.central_header[SIZECENTRALHEADER+i] = filename[i];
    for (i = 0; i < size_extrafield_global; i++)
        zi->ci.central_header[SIZECENTRALHEADER+size_filename+i] =
            ((const char*)extrafield_global)[i];

    /* Store comment at the end for later repositioning */
    for (i = 0; i < size_comment; i++)
        zi->ci.central_header[zi->ci.size_centralheader+
            zi->ci.size_centralextrafree+i] = comment[i];

    if (zi->ci.central_header == NULL)
        return ZIP_INTERNALERROR;

    /* Write the local header */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)LOCALHEADERMAGIC, 4);

    if (err == ZIP_OK)
    {
        if (zi->ci.zip64)
            err = zipWriteValue(zi->stream, (uint16_t)45, 2); /* version needed to extract */
        else
            err = zipWriteValue(zi->stream, (uint16_t)20, 2); /* version needed to extract */
    }
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, zi->ci.flag, 2);
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, zi->ci.method, 2);
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, zi->ci.dos_date, 4);

    /* CRC & compressed size & uncompressed size is in data descriptor */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)0, 4); /* crc 32, unknown */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)0, 4); /* compressed size, unknown */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)0, 4); /* uncompressed size, unknown */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, size_filename, 2);
    if (err == ZIP_OK)
    {
        uint64_t size_extrafield = size_extrafield_local;
#ifdef HAVE_AES
        if (zi->ci.method == AES_METHOD)
            size_extrafield += 11;
#endif
        err = zipWriteValue(zi->stream, (uint16_t)size_extrafield, 2);
    }
    if ((err == ZIP_OK) && (size_filename > 0))
    {
        if (mz_stream_write(zi->stream, filename, size_filename) != size_filename)
            err = ZIP_ERRNO;
    }
    if ((err == ZIP_OK) && (size_extrafield_local > 0))
    {
        if (mz_stream_write(zi->stream, extrafield_local, size_extrafield_local) != size_extrafield_local)
            err = ZIP_ERRNO;
    }

#ifdef HAVE_AES
    /* Write the AES extended info */
    if ((err == ZIP_OK) && (zi->ci.method == AES_METHOD))
    {
        int headerid = 0x9901;
        short datasize = 7;

        err = zipWriteValue(zi->stream, headerid, 2);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, datasize, 2);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, AES_VERSION, 2);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, 'A', 1);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, 'E', 1);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, AES_ENCRYPTIONMODE, 1);
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->ci.compression_method, 2);
    }
#endif

    zi->ci.crc32 = 0;
    zi->ci.stream_initialised = 0;
    zi->ci.total_compressed = 0;
    zi->ci.total_uncompressed = 0;

#ifndef NOCRYPT
    if (err == Z_OK)
    {
        if (password == NULL)
        {
            mz_stream_passthru_create(&zi->ci.crypt_stream);
            mz_stream_set_base(zi->ci.crypt_stream, zi->stream);
        }
#ifdef HAVE_AES
        else if (zi->ci.method == AES_METHOD)
        {
            mz_stream_aes_create(&zi->ci.crypt_stream);
            mz_stream_aes_set_password(zi->ci.crypt_stream, password);
            
            mz_stream_set_base(zi->ci.crypt_stream, zi->stream);

            if (mz_stream_aes_open(zi->ci.crypt_stream, NULL, MZ_STREAM_MODE_WRITE) == MZ_STREAM_ERR)
                err = ZIP_ERRNO;
        }
        else
#endif
        {
            uint8_t verify1 = 0;
            uint8_t verify2 = 0;

            /*
            Info-ZIP modification to ZipCrypto format:
            If bit 3 of the general purpose bit flag is set, it uses high byte of 16-bit File Time. 
            */
            verify1 = (uint8_t)((zi->ci.dos_date >> 16) & 0xff);
            verify2 = (uint8_t)((zi->ci.dos_date >> 8) & 0xff);

            mz_stream_crypt_create(&zi->ci.crypt_stream);
            mz_stream_crypt_set_password(zi->ci.crypt_stream, password);
            mz_stream_crypt_set_verify(zi->ci.crypt_stream, verify1, verify2);

            mz_stream_set_base(zi->ci.crypt_stream, zi->stream);

            if (mz_stream_crypt_open(zi->ci.crypt_stream, NULL, MZ_STREAM_MODE_WRITE) == MZ_STREAM_ERR)
                err = ZIP_ERRNO;
        }
    }
#endif

    if (err == ZIP_OK)
    {
        if (zi->ci.raw)
        {
            mz_stream_passthru_create(&zi->ci.compress_stream);
            mz_stream_set_base(zi->ci.compress_stream, zi->ci.crypt_stream);
        }
        else if (method == Z_DEFLATED)
        {
            mz_stream_zlib_create(&zi->ci.compress_stream);
            //mz_stream_zlib_set_level(zi->ci.compress_stream, level);
            //mz_stream_zlib_set_window_bits(zi->ci.compress_stream, windowBits);
            //mz_stream_zlib_set_strategy(zi->ci.compress_stream, strategy);

            mz_stream_set_base(zi->ci.compress_stream, zi->ci.crypt_stream);

            if (mz_stream_open(zi->ci.compress_stream, NULL, MZ_STREAM_MODE_WRITE) == MZ_STREAM_ERR)
                err = ZIP_ERRNO;

            if (err == Z_OK)
                zi->ci.stream_initialised = Z_DEFLATED;
        }
        else if (method == Z_BZIP2ED)
        {
#ifdef HAVE_BZIP2
            zi->ci.bstream.bzalloc = 0;
            zi->ci.bstream.bzfree = 0;
            zi->ci.bstream.opaque = (voidpf)0;

            err = BZ2_bzCompressInit(&zi->ci.bstream, level, 0, 35);
            if (err == BZ_OK)
                zi->ci.stream_initialised = Z_BZIP2ED;
#endif
        }
    }


    if (err == Z_OK)
    {
        mz_stream_crc32_create(&zi->ci.crc32_stream);
        mz_stream_set_base(zi->ci.crc32_stream, zi->ci.compress_stream);

        if (mz_stream_crc32_open(zi->ci.crc32_stream, NULL, MZ_STREAM_MODE_WRITE) == MZ_STREAM_ERR)
            err = ZIP_ERRNO;
    }

    if (err == Z_OK)
        zi->in_opened_file_inzip = 1;

    return err;
}
#define DEF_MEM_LEVEL 8
extern int ZEXPORT zipOpenNewFileInZip4(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, uint16_t version_madeby, uint16_t flag_base)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel,
        strategy, password, crc_for_crypting, version_madeby, flag_base, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel,
        strategy, password, crc_for_crypting, VERSIONMADEBY, 0, 0);
}

extern int ZEXPORT zipOpenNewFileInZip3_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int windowBits,
    int memLevel, int strategy, const char *password, ZIP_UNUSED uint32_t crc_for_crypting, int zip64)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, windowBits, memLevel, strategy,
        password, crc_for_crypting, VERSIONMADEBY, 0, zip64);
}

extern int ZEXPORT zipOpenNewFileInZip2(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, -MAX_WBITS, DEF_MEM_LEVEL,
        Z_DEFAULT_STRATEGY, NULL, 0, VERSIONMADEBY, 0, 0);
}

extern int ZEXPORT zipOpenNewFileInZip2_64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int raw, int zip64)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, raw, -MAX_WBITS, DEF_MEM_LEVEL,
        Z_DEFAULT_STRATEGY, NULL, 0, VERSIONMADEBY, 0, zip64);
}

extern int ZEXPORT zipOpenNewFileInZip64(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level, int zip64)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, 0, -MAX_WBITS, DEF_MEM_LEVEL,
        Z_DEFAULT_STRATEGY, NULL, 0, VERSIONMADEBY, 0, zip64);
}

extern int ZEXPORT zipOpenNewFileInZip(zipFile file, const char *filename, const zip_fileinfo *zipfi,
    const void *extrafield_local, uint16_t size_extrafield_local, const void *extrafield_global,
    uint16_t size_extrafield_global, const char *comment, uint16_t method, int level)
{
    return zipOpenNewFileInZip4_64(file, filename, zipfi, extrafield_local, size_extrafield_local,
        extrafield_global, size_extrafield_global, comment, method, level, 0, -MAX_WBITS, DEF_MEM_LEVEL,
        Z_DEFAULT_STRATEGY, NULL, 0, VERSIONMADEBY, 0, 0);
}

/* Flushes the write buffer to disk 
static int zipFlushWriteBuffer(zip64_internal *zi)
{
    uint64_t size_available = 0;
    uint32_t total_written = 0;
    uint32_t written = 0;
    uint32_t write = 0;
    uint32_t max_write = 0;
    int err = ZIP_OK;

    do
    {
        max_write = write;

        if (zi->disk_size > 0)
        {
            zipGetDiskSizeAvailable((zipFile)zi, &size_available);

            if (size_available == 0)
            {
                err = zipGoToNextDisk((zipFile)zi);
                if (err != ZIP_OK)
                    return err;
            }

            if (size_available < (uint64_t)max_write)
                max_write = (uint32_t)size_available;
        }

        written = mz_stream_write(zi->ci.crypt_stream, zi->ci.buffered_data + total_written, max_write);
        if (written != max_write)
        {
            err = ZIP_ERRNO;
            break;
        }

        total_written += written;
        write -= written;
    }
    while (write > 0);

    zi->ci.total_compressed += zi->ci.pos_in_buffered_data;

#ifdef HAVE_BZIP2
    if (zi->ci.compression_method == Z_BZIP2ED)
    {
        zi->ci.total_uncompressed += zi->ci.bstream.total_in_lo32;
        zi->ci.bstream.total_in_lo32 = 0;
        zi->ci.bstream.total_in_hi32 = 0;
    }
    else
#endif
    {
        zi->ci.total_uncompressed += zi->ci.stream.total_in;
        zi->ci.stream.total_in = 0;
    }

    zi->ci.pos_in_buffered_data = 0;

    return err;
}*/

extern int ZEXPORT zipWriteInFileInZip(zipFile file, const void *buf, uint32_t len)
{
    zip64_internal *zi = NULL;
    int16_t err = ZIP_OK;

    if (file == NULL)
        return ZIP_PARAMERROR;
    zi = (zip64_internal*)file;

    if (zi->in_opened_file_inzip == 0)
        return ZIP_PARAMERROR;

    if (mz_stream_write(zi->ci.crc32_stream, buf, len) == MZ_STREAM_ERR)
        err = ZIP_ERRNO;

    return err;
}

extern int ZEXPORT zipCloseFileInZipRaw64(zipFile file, uint64_t uncompressed_size, uint32_t crc32)
{
    zip64_internal *zi = NULL;
    uint16_t extra_data_size = 0;
    uint32_t i = 0;
    uint64_t compressed_size = 0;
    unsigned char *extra_info = NULL;
    int err = ZIP_OK;

    if (file == NULL)
        return ZIP_PARAMERROR;
    zi = (zip64_internal*)file;

    if (zi->in_opened_file_inzip == 0)
        return ZIP_PARAMERROR;
  
    mz_stream_close(zi->ci.compress_stream);
    
    if (!zi->ci.raw)
    {
        crc32 = mz_stream_crc32_get_value(zi->ci.crc32_stream);

        uncompressed_size = mz_stream_crc32_get_total_out(zi->ci.crc32_stream);
        compressed_size = mz_stream_zlib_get_total_out(zi->ci.compress_stream);
    }

    if (zi->ci.flag & 1)
    {
        mz_stream_set_base(zi->ci.crypt_stream, zi->stream);

        if (mz_stream_close(zi->ci.crypt_stream) == MZ_STREAM_ERR)
            err = ZIP_ERRNO;

        mz_stream_delete(&zi->ci.crypt_stream);
    }

    mz_stream_delete(&zi->ci.compress_stream);
    mz_stream_crc32_delete(&zi->ci.crc32_stream);

    /* Write data descriptor */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)DATADESCRIPTORMAGIC, 4);
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, crc32, 4);
    if (err == ZIP_OK)
    {
        if (zi->ci.zip64)
            err = zipWriteValue(zi->stream, compressed_size, 8);
        else
            err = zipWriteValue(zi->stream, (uint32_t)compressed_size, 4);
    }
    if (err == ZIP_OK)
    {
        if (zi->ci.zip64)
            err = zipWriteValue(zi->stream, uncompressed_size, 8);
        else
            err = zipWriteValue(zi->stream, (uint32_t)uncompressed_size, 4);
    }

    /* Update crc and sizes to central directory */
    zipWriteValueToMemory(zi->ci.central_header + 16, crc32, 4); /* crc */
    if (zi->ci.total_compressed >= UINT32_MAX)
        zipWriteValueToMemory(zi->ci.central_header + 20, UINT32_MAX, 4); /* compr size */
    else
        zipWriteValueToMemory(zi->ci.central_header + 20, zi->ci.total_compressed, 4); /* compr size */
    if (uncompressed_size >= UINT32_MAX)
        zipWriteValueToMemory(zi->ci.central_header + 24, UINT32_MAX, 4); /* uncompr size */
    else
        zipWriteValueToMemory(zi->ci.central_header + 24, uncompressed_size, 4); /* uncompr size */
    //if (zi->ci.stream.data_type == Z_ASCII)
    //    zipWriteValueToMemory(zi->ci.central_header + 36, (uint16_t)Z_ASCII, 2); /* internal file attrib */

    /* Add ZIP64 extra info field for uncompressed size */
    if (uncompressed_size >= UINT32_MAX)
        extra_data_size += 8;
    /* Add ZIP64 extra info field for compressed size */
    if (zi->ci.total_compressed >= UINT32_MAX)
        extra_data_size += 8;
    /* Add ZIP64 extra info field for relative offset to local file header of current file */
    if (zi->ci.pos_local_header >= UINT32_MAX)
        extra_data_size += 8;

    /* Add ZIP64 extra info header to central directory */
    if (extra_data_size > 0)
    {
        if ((uint32_t)(extra_data_size + 4) > zi->ci.size_centralextrafree)
            return ZIP_BADZIPFILE;

        extra_info = (unsigned char*)zi->ci.central_header + zi->ci.size_centralheader;

        zipWriteValueToMemoryAndMove(&extra_info, 0x0001, 2);
        zipWriteValueToMemoryAndMove(&extra_info, extra_data_size, 2);

        if (uncompressed_size >= UINT32_MAX)
            zipWriteValueToMemoryAndMove(&extra_info, uncompressed_size, 8);
        if (zi->ci.total_compressed >= UINT32_MAX)
            zipWriteValueToMemoryAndMove(&extra_info, zi->ci.total_compressed, 8);
        if (zi->ci.pos_local_header >= UINT32_MAX)
            zipWriteValueToMemoryAndMove(&extra_info, zi->ci.pos_local_header, 8);

        zi->ci.size_centralextrafree -= extra_data_size + 4;
        zi->ci.size_centralheader += extra_data_size + 4;
        zi->ci.size_centralextra += extra_data_size + 4;

        zipWriteValueToMemory(zi->ci.central_header + 30, zi->ci.size_centralextra, 2);
    }

#ifdef HAVE_AES
    /* Write AES extra info header to central directory */
    if (zi->ci.method == AES_METHOD)
    {
        extra_info = (unsigned char*)zi->ci.central_header + zi->ci.size_centralheader;
        extra_data_size = 7;

        if ((uint32_t)(extra_data_size + 4) > zi->ci.size_centralextrafree)
            return ZIP_BADZIPFILE;

        zipWriteValueToMemoryAndMove(&extra_info, 0x9901, 2);
        zipWriteValueToMemoryAndMove(&extra_info, extra_data_size, 2);
        zipWriteValueToMemoryAndMove(&extra_info, AES_VERSION, 2);
        zipWriteValueToMemoryAndMove(&extra_info, 'A', 1);
        zipWriteValueToMemoryAndMove(&extra_info, 'E', 1);
        zipWriteValueToMemoryAndMove(&extra_info, AES_ENCRYPTIONMODE, 1);
        zipWriteValueToMemoryAndMove(&extra_info, zi->ci.compression_method, 2);

        zi->ci.size_centralextrafree -= extra_data_size + 4;
        zi->ci.size_centralheader += extra_data_size + 4;
        zi->ci.size_centralextra += extra_data_size + 4;

        zipWriteValueToMemory(zi->ci.central_header + 30, zi->ci.size_centralextra, 2);
    }
#endif
    /* Restore comment to correct position */
    for (i = 0; i < zi->ci.size_comment; i++)
        zi->ci.central_header[zi->ci.size_centralheader+i] =
            zi->ci.central_header[zi->ci.size_centralheader+zi->ci.size_centralextrafree+i];
    zi->ci.size_centralheader += zi->ci.size_comment;

    if (err == ZIP_OK)
        err = add_data_in_datablock(&zi->central_dir, zi->ci.central_header, zi->ci.size_centralheader);

    free(zi->ci.central_header);

    zi->number_entry++;
    zi->in_opened_file_inzip = 0;

    return err;
}

extern int ZEXPORT zipCloseFileInZipRaw(zipFile file, uint32_t uncompressed_size, uint32_t crc32)
{
    return zipCloseFileInZipRaw64(file, uncompressed_size, crc32);
}

extern int ZEXPORT zipCloseFileInZip(zipFile file)
{
    return zipCloseFileInZipRaw(file, 0, 0);
}

extern int ZEXPORT zipClose(zipFile file, const char *global_comment)
{
    return zipClose_64(file, global_comment);
}

extern int ZEXPORT zipClose_64(zipFile file, const char *global_comment)
{
    return zipClose2_64(file, global_comment, VERSIONMADEBY);
}

extern int ZEXPORT zipClose2_64(zipFile file, const char *global_comment, uint16_t version_madeby)
{
    zip64_internal *zi = NULL;
    uint32_t size_centraldir = 0;
    uint16_t size_global_comment = 0;
    uint64_t centraldir_pos_inzip = 0;
    uint64_t pos = 0;
    uint64_t cd_pos = 0;
    uint32_t write = 0;
    int err = ZIP_OK;

    if (file == NULL)
        return ZIP_PARAMERROR;
    zi = (zip64_internal*)file;

    if (zi->in_opened_file_inzip == 1)
        err = zipCloseFileInZip(file);

#ifndef NO_ADDFILEINEXISTINGZIP
    if (global_comment == NULL)
        global_comment = zi->globalcomment;
#endif

    if (zi->stream != zi->stream_cd)
    {
        if (mz_stream_close(zi->stream) != 0)
            if (err == ZIP_OK)
                err = ZIP_ERRNO;
        if (zi->disk_size > 0)
            zi->number_disk_with_CD = zi->number_disk + 1;
        zi->stream = zi->stream_cd;
    }

    centraldir_pos_inzip = mz_stream_tell(zi->stream);

    if (err == ZIP_OK)
    {
        linkedlist_datablock_internal *ldi = zi->central_dir.first_block;
        while (ldi != NULL)
        {
            if ((err == ZIP_OK) && (ldi->filled_in_this_block > 0))
            {
                write = mz_stream_write(zi->stream, ldi->data, ldi->filled_in_this_block);
                if (write != ldi->filled_in_this_block)
                    err = ZIP_ERRNO;
            }

            size_centraldir += ldi->filled_in_this_block;
            ldi = ldi->next_datablock;
        }
    }

    free_linkedlist(&(zi->central_dir));

    pos = centraldir_pos_inzip - zi->add_position_when_writting_offset;

    /* Write the ZIP64 central directory header */
    if (pos >= UINT32_MAX || zi->number_entry > UINT32_MAX)
    {
        uint64_t zip64_eocd_pos_inzip = mz_stream_tell(zi->stream);
        uint32_t zip64_datasize = 44;

        err = zipWriteValue(zi->stream, (uint32_t)ZIP64ENDHEADERMAGIC, 4);

        /* Size of this 'zip64 end of central directory' */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, (uint64_t)zip64_datasize, 8);
        /* Version made by */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, version_madeby, 2);
        /* version needed */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, (uint16_t)45, 2);
        /* Number of this disk */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_disk_with_CD, 4);
        /* Number of the disk with the start of the central directory */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_disk_with_CD, 4);
        /* Total number of entries in the central dir on this disk */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_entry, 8);
        /* Total number of entries in the central dir */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_entry, 8);
        /* Size of the central directory */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, (uint64_t)size_centraldir, 8);

        if (err == ZIP_OK)
        {
            /* Offset of start of central directory with respect to the starting disk number */
            cd_pos = centraldir_pos_inzip - zi->add_position_when_writting_offset;
            err = zipWriteValue(zi->stream, cd_pos, 8);
        }
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, (uint32_t)ZIP64ENDLOCHEADERMAGIC, 4);

        /* Number of the disk with the start of the central directory */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_disk_with_CD, 4);
        /* Relative offset to the Zip64EndOfCentralDirectory */
        if (err == ZIP_OK)
        {
            cd_pos = zip64_eocd_pos_inzip - zi->add_position_when_writting_offset;
            err = zipWriteValue(zi->stream, cd_pos, 8);
        }
        /* Number of the disk with the start of the central directory */
        if (err == ZIP_OK)
            err = zipWriteValue(zi->stream, zi->number_disk_with_CD + 1, 4);
    }

    /* Write the central directory header */

    /* Signature */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint32_t)ENDHEADERMAGIC, 4);
    /* Number of this disk */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint16_t)zi->number_disk_with_CD, 2);
    /* Number of the disk with the start of the central directory */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, (uint16_t)zi->number_disk_with_CD, 2);
    /* Total number of entries in the central dir on this disk */
    if (err == ZIP_OK)
    {
        if (zi->number_entry >= UINT16_MAX)
            err = zipWriteValue(zi->stream, UINT16_MAX, 2); /* use value in ZIP64 record */
        else
            err = zipWriteValue(zi->stream, (uint16_t)zi->number_entry, 2);
    }
    /* Total number of entries in the central dir */
    if (err == ZIP_OK)
    {
        if (zi->number_entry >= UINT16_MAX)
            err = zipWriteValue(zi->stream, UINT16_MAX, 2); /* use value in ZIP64 record */
        else
            err = zipWriteValue(zi->stream, (uint16_t)zi->number_entry, 2);
    }
    /* Size of the central directory */
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, size_centraldir, 4);
    /* Offset of start of central directory with respect to the starting disk number */
    if (err == ZIP_OK)
    {
        cd_pos = centraldir_pos_inzip - zi->add_position_when_writting_offset;
        if (pos >= UINT32_MAX)
            err = zipWriteValue(zi->stream, UINT32_MAX, 4);
        else
            err = zipWriteValue(zi->stream, (uint32_t)cd_pos, 4);
    }

    /* Write global comment */

    if (global_comment != NULL)
        size_global_comment = (uint16_t)strlen(global_comment);
    if (err == ZIP_OK)
        err = zipWriteValue(zi->stream, size_global_comment, 2);
    if (err == ZIP_OK && size_global_comment > 0)
    {
        if (mz_stream_write(zi->stream, global_comment, size_global_comment) != size_global_comment)
            err = ZIP_ERRNO;
    }

    if ((mz_stream_close(zi->stream) != 0) && (err == ZIP_OK))
        err = ZIP_ERRNO;

#ifndef NO_ADDFILEINEXISTINGZIP
    TRYFREE(zi->globalcomment);
#endif
    TRYFREE(zi);

    return err;
}
