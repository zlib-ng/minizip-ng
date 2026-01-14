/* mz_strm_ppmd.c -- Stream for PPMd compress/decompress
   part of the minizip-ng project

   Copyright (C) Nathan Moinvaziri
      https://github.com/zlib-ng/minizip-ng

   This program is distributed under the terms of the same license as zlib.
   See the accompanying LICENSE file for the full text of the license.
*/

#include <sys/param.h>  // for MIN()
#include <assert.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_ppmd.h"

#include "C/Ppmd8.h"
#include "C/7zTypes.h"

/***************************************************************************/

static mz_stream_vtbl mz_stream_ppmd_vtbl = {
    mz_stream_ppmd_open,   mz_stream_ppmd_is_open, mz_stream_ppmd_read,           mz_stream_ppmd_write,
    mz_stream_ppmd_tell,   mz_stream_ppmd_seek,    mz_stream_ppmd_close,          mz_stream_ppmd_error,
    mz_stream_ppmd_create, mz_stream_ppmd_delete,  mz_stream_ppmd_get_prop_int64, mz_stream_ppmd_set_prop_int64};

/***************************************************************************/

#define PPMD_PRESET_DEFAULT 9  // Should match default in7-Zip

/***************************************************************************/

typedef struct mz_InBuffer_s {
    const void *src; /**< start of input buffer */
    size_t size;     /**< size of input buffer */
    size_t pos;      /**< position where reading stopped. Will be updated. Necessarily 0 <= pos <= size */
} mz_InBuffer;

typedef struct mz_OutBuffer_s {
    void *dst;   /**< start of output buffer */
    size_t size; /**< size of output buffer */
    size_t pos;  /**< position where writing stopped. Will be updated. Necessarily 0 <= pos <= size */
} mz_OutBuffer;

typedef struct mz_ppmd_info_s {
    /* hold CPpmd8 or CPpmd7 struct pointer */
    void *cPpmd;
    void *rc;
    mz_InBuffer *in;
    mz_OutBuffer *out;
    int max_length;
    int result;
    void *t;
} mz_ppmd_info;

typedef struct {
    /* Inherits from IByteIn */
    Byte (*Read)(void *p);
    mz_InBuffer *inBuffer;
    void *t;
} mz_BufferReader;

typedef struct {
    /* Inherits from IByteOut */
    void (*Write)(void *p, Byte b);
    mz_OutBuffer *outBuffer;
    mz_ppmd_info *t;
} mz_BufferWriter;

typedef struct mz_stream_ppmd_s {
    mz_stream stream;
    CPpmd8 ppmd8;
    uint8_t buffer[INT16_MAX];
    int64_t total_in;
    int64_t total_out;
    int64_t max_total_in;
    int32_t mode;
    int32_t error;
    int8_t initialized;
    ISzAlloc allocator;

    // Write specific
    mz_BufferWriter writer;
    mz_OutBuffer out;
    int32_t preset;  // PPMD uses theterm level for this

    // Read Specific
    mz_BufferReader reader;
    mz_InBuffer in;
    int8_t end_stream;

} mz_stream_ppmd;

/***************************************************************************/

/* malloc wrapper for PPMD library */
static void *mz_ppmd_alloc_func(const ISzAlloc *p, size_t size) {
    MZ_UNUSED(p);
    return malloc(size);
}

/* free wrapper for PPMD library */
static void mz_ppmd_free_func(const ISzAlloc *p, void *address) {
    MZ_UNUSED(p);
    free(address);
}

#ifndef MZ_ZIP_NO_COMPRESSION

static void Writer(const void *p, Byte b) {
    mz_BufferWriter *bufferWriter = (mz_BufferWriter *)p;
    if (bufferWriter->outBuffer->size == bufferWriter->outBuffer->pos) {
        return;
    }
    *((Byte *)bufferWriter->outBuffer->dst + bufferWriter->outBuffer->pos++) = b;
}

static int32_t mz_stream_ppmd_flush(void *stream) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;

    if (ppmd->out.pos) {
        if (mz_stream_write(ppmd->stream.base, ppmd->out.dst, ppmd->out.pos) != ppmd->out.pos)
            return MZ_WRITE_ERROR;
        ppmd->total_out += ppmd->out.pos;
        ppmd->out.pos = 0;
    }

    return MZ_OK;
}

static void mz_setup_buffered_writer(mz_stream_ppmd *ppmd) {
    ppmd->out.dst = ppmd->buffer;
    ppmd->out.size = sizeof(ppmd->buffer);  // INT16_MAX;
    ppmd->out.pos = 0;

    ppmd->writer.Write = (void (*)(void *, Byte))Writer;
    ppmd->writer.outBuffer = &ppmd->out;
    ppmd->ppmd8.Stream.Out = (IByteOut *)&ppmd->writer;
}
#endif

#ifndef MZ_ZIP_NO_DECOMPRESSION

static Byte Reader(void *p) {
    mz_BufferReader *bufferReader = (mz_BufferReader *)p;
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)bufferReader->t;
    uint8_t b;
    int32_t status;

    // mz_stream_read_uint8( (mz_stream_ppmd *)ppmd->stream.base, &b));
    if ((status = mz_stream_read_uint8((mz_stream_ppmd *)ppmd->stream.base, &b)) != MZ_OK) {
        // TODO - don't think this can ever happen?

        if (b == -1)  // EOF
            ppmd->end_stream = 1;
        else
            ppmd->error = status;
        b = 0;
    } else
        ++ppmd->total_in;

    return (Byte)b;
}

static void mz_setup_buffered_reader(mz_stream_ppmd *ppmd) {
    ppmd->in.src = ppmd->buffer;
    ppmd->in.size = sizeof(ppmd->buffer);  // INT16_MAX;
    ppmd->in.pos = 0;

    ppmd->reader.Read = Reader;
    ppmd->reader.inBuffer = &ppmd->in;
    ppmd->ppmd8.Stream.In = (IByteIn *)&ppmd->reader;

    ppmd->reader.t = ppmd;
}

#endif

int32_t mz_stream_ppmd_open(void *stream, const char *path, int32_t mode) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;

    MZ_UNUSED(path);

    Ppmd8_Construct(&ppmd->ppmd8);

    if (mode & MZ_OPEN_MODE_WRITE) {
#ifdef MZ_ZIP_NO_COMPRESSION
        MZ_UNUSED(stream);
        return MZ_SUPPORT_ERROR;
#else

        /* PPMD8_MIN_ORDER (= 2) <= order <= PPMD8_MAX_ORDER (= 16)
         * 1MB (= 2* 0) <= memSize <= 256MB (= 2^ 8)   (M = 2^ 20)
         * restor = 0 (PPMD8_RESTORE_METHOD_RESTART),
         *          1 (PPMD8_RESTORE_METHOD_CUT_OFF)
         *
         * Currently using 7-Zip-compatible values:
         *    order = 3 + level
         *    memory size = 2^ (level- 1) (MB)  (level 9 treated as level 8.)
         *    restoration method = 0 for level <= 6, 1 for level >= 7.
         *
         */

        /* PPMd parameters. */
        unsigned order;
        unsigned memSize;
        unsigned restor;
        unsigned short ppmd_param_word;

        if (ppmd->preset < PPMD8_MIN_ORDER || ppmd->preset > PPMD8_MAX_ORDER)
            return MZ_OPEN_ERROR;

        mz_setup_buffered_writer(ppmd);

        order = ppmd->preset;                      /* 4, 5, 6, ..., 12. */
        memSize = 1 << (MIN(ppmd->preset, 8) - 1); /* 1MB, 2MB, 4MB, ..., 128MB. */
        restor = (ppmd->preset <= 6 ? 0 : 1);

        memSize <<= 20; /* Convert B to MB. */

        if (!Ppmd8_Alloc(&ppmd->ppmd8, memSize, &ppmd->allocator)) {
            return MZ_MEM_ERROR;
        }

        Ppmd8_RangeEnc_Init(&ppmd->ppmd8);
        Ppmd8_Init(&ppmd->ppmd8, order, restor);

        /* wPPMd = (Model order - 1) +
         *         ((Sub-allocator size - 1) << 4) +
         *         (Model restoration method << 12)
         *
         *  15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
         *  Mdl_Res_Mth ___Sub-allocator_size-1 Mdl_Order-1
         */

        /* Form the PPMd properties word.  Put out the bytes. */
        ppmd_param_word = ((order - 1) & 0xf) + ((((memSize >> 20) - 1) & 0xff) << 4) + ((restor & 0xf) << 12);

        // write header bytes directly to output buffer, bypassing the compression code
        // These bytes will be included in the compressed size stored in the zip metadata.

        ((uint8_t *)ppmd->out.dst)[0] = (Byte)(ppmd_param_word & 0xff);
        ((uint8_t *)ppmd->out.dst)[1] = (Byte)(ppmd_param_word >> 8);
        ppmd->out.pos += 2;
        mz_stream_ppmd_flush(ppmd);
#endif
    } else if (mode & MZ_OPEN_MODE_READ) {
#ifdef MZ_ZIP_NO_DECOMPRESSION
        MZ_UNUSED(stream);
        return MZ_SUPPORT_ERROR;
#else

        unsigned char ppmd_props[2]; /* PPMd properties. */
        uint16_t ppmd_prop_word;     /* PPMd properties. */

        /* Initialize the 7-Zip I/O structure. */
        mz_setup_buffered_reader(ppmd);

        /* Read & parse the 2 PPMD header bytes into a 16-bit word */
        if (mz_stream_read_uint8(ppmd->stream.base, &ppmd_props[0]) != MZ_OK ||
            mz_stream_read_uint8(ppmd->stream.base, &ppmd_props[1]) != MZ_OK)
            return MZ_STREAM_ERROR;
        ppmd_prop_word = ppmd_props[0] | (ppmd_props[1] << 8);
        ppmd->total_in += 2;

        /* wPPMd = (Model order - 1) +
         *         ((Sub-allocator size - 1) << 4) +
         *         (Model restoration method << 12)
         *
         *  15 14 13 12 11 10 09 08 07 06 05 04 03 02 01 00
         *  Mdl_Res_Mth ___Sub-allocator_size-1 Mdl_Order-1
         */
        unsigned order = (ppmd_prop_word & 0xf) + 1;
        unsigned memSize = ((ppmd_prop_word >> 4) & 0xff) + 1;
        unsigned restor = (ppmd_prop_word >> 12);

        /* Convert archive MB value into raw byte value. */
        memSize <<= 20;

        if ((order < PPMD8_MIN_ORDER) || (order > PPMD8_MAX_ORDER))
            return MZ_STREAM_ERROR;

        if (!Ppmd8_Alloc(&ppmd->ppmd8, memSize, &ppmd->allocator))
            return MZ_STREAM_ERROR;

        if (!Ppmd8_RangeDec_Init(&ppmd->ppmd8))
            return MZ_STREAM_ERROR;

        Ppmd8_Init(&ppmd->ppmd8, order, restor);
#endif
    }

    ppmd->initialized = 1;
    ppmd->mode = mode;

    return MZ_OK;
}

int32_t mz_stream_ppmd_is_open(void *stream) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;
    if (ppmd->initialized != 1)
        return MZ_OPEN_ERROR;
    return MZ_OK;
}

int32_t mz_stream_ppmd_read(void *stream, void *buf, int32_t size) {
#ifdef MZ_ZIP_NO_DECOMPRESSION
    MZ_UNUSED(stream);
    MZ_UNUSED(buf);
    MZ_UNUSED(size);
    return MZ_SUPPORT_ERROR;
#else
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;
    unsigned char *next_out = buf; /* Output buffer pointer. */
    unsigned avail_out = size;     /* Output buffer size. */

    int sym = 0;
    int32_t written = 0;

    if (ppmd->end_stream)
        return MZ_OK;

    /* Decode input to fill the output buffer. */
    for (avail_out = size; avail_out > 0; avail_out--) {
        sym = Ppmd8_DecodeSymbol(&ppmd->ppmd8);
        ;

        if (sym < 0 || ppmd->end_stream || ppmd->error)
            break;

        *(next_out++) = sym;
        ++written;
    }

    if (sym == -1) {
        // end_stream
        ppmd->end_stream = 1;

        // Drop through and return ritten bytes
    } else if (sym == -2) {
        /* Insufficient input data. */
        return MZ_STREAM_ERROR;
    } else if (ppmd->error) {
        /* Invalid end of input data? */
        return ppmd->error;
    }

    ppmd->total_out += written;
    return written;
#endif
}

int32_t mz_stream_ppmd_write(void *stream, const void *buf, int32_t size) {
#ifdef MZ_ZIP_NO_COMPRESSION
    MZ_UNUSED(stream);
    MZ_UNUSED(buf);
    MZ_UNUSED(size);
    return MZ_SUPPORT_ERROR;
#else
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;
    const uint8_t *buf_ptr = (const uint8_t *)buf;
    int32_t bytes_written = 0;

    mz_setup_buffered_writer(ppmd);
    for (bytes_written = 0; bytes_written < size; bytes_written++) {
        if (ppmd->out.pos == ppmd->out.size) {
            if (mz_stream_ppmd_flush(ppmd) != MZ_OK)
                return MZ_WRITE_ERROR;
        }

        Ppmd8_EncodeSymbol(&ppmd->ppmd8, buf_ptr[bytes_written]);
    }
    ppmd->total_in += size;

    if (mz_stream_ppmd_flush(stream) != MZ_OK)
        return MZ_WRITE_ERROR;

    return size;
#endif
}

int64_t mz_stream_ppmd_tell(void *stream) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;
    return ppmd->total_in;
}

int32_t mz_stream_ppmd_seek(void *stream, int64_t offset, int32_t origin) {
    MZ_UNUSED(stream);
    MZ_UNUSED(offset);
    MZ_UNUSED(origin);

    return MZ_SEEK_ERROR;
}

int32_t mz_stream_ppmd_close(void *stream) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;

#ifndef MZ_ZIP_NO_COMPRESSION
    if (ppmd->mode & MZ_OPEN_MODE_WRITE) {
        mz_setup_buffered_writer(ppmd);

        /* Encode end marker */
        Ppmd8_EncodeSymbol(&ppmd->ppmd8, -1);

        Ppmd8_RangeEnc_FlushData(&ppmd->ppmd8);

        /* Flush any remaining buffered output */
        mz_stream_ppmd_flush(stream);
    }
#endif

    Ppmd8_Free(&ppmd->ppmd8, &ppmd->allocator);

    ppmd->initialized = 0;

    return MZ_OK;
}

int32_t mz_stream_ppmd_error(void *stream) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;
    return ppmd->error;
}

int32_t mz_stream_ppmd_get_prop_int64(void *stream, int32_t prop, int64_t *value) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;

    switch (prop) {
    case MZ_STREAM_PROP_TOTAL_IN:
        *value = ppmd->total_in;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_OUT:
        *value = ppmd->total_out;
        return MZ_OK;
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        *value = ppmd->max_total_in;
        return MZ_OK;
    }

    return MZ_PARAM_ERROR;
}

int32_t mz_stream_ppmd_set_prop_int64(void *stream, int32_t prop, int64_t value) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)stream;

    switch (prop) {
    case MZ_STREAM_PROP_TOTAL_IN_MAX:
        ppmd->max_total_in = value;  // TODO -- see what this can get used for in PPMd
        return MZ_OK;
    case MZ_STREAM_PROP_COMPRESS_LEVEL:
        if (value == MZ_COMPRESS_LEVEL_DEFAULT)
            ppmd->preset = PPMD_PRESET_DEFAULT;
        else
            ppmd->preset = (int16_t)value;
        return MZ_OK;
    }

    return MZ_PARAM_ERROR;
}

void *mz_stream_ppmd_create(void) {
    mz_stream_ppmd *ppmd = (mz_stream_ppmd *)calloc(1, sizeof(mz_stream_ppmd));
    if (ppmd) {
        ppmd->stream.vtbl = &mz_stream_ppmd_vtbl;
        ppmd->allocator.Alloc = mz_ppmd_alloc_func;
        ppmd->allocator.Free = mz_ppmd_free_func;
        ppmd->preset = PPMD_PRESET_DEFAULT;
    }
    return ppmd;
}

void mz_stream_ppmd_delete(void **stream) {
    mz_stream_ppmd *ppmd = NULL;
    if (!stream)
        return;
    ppmd = (mz_stream_ppmd *)*stream;
    free(ppmd);
    *stream = NULL;
}

void *mz_stream_ppmd_get_interface(void) {
    return (void *)&mz_stream_ppmd_vtbl;
}

/***************************************************************************/
