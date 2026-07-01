#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"

#include "ioapi.h"

typedef struct mz_stream_ioapi_s {
    mz_stream stream;
    void *handle;
    zlib_filefunc_def filefunc;
    zlib_filefunc64_def filefunc64;
} mz_stream_ioapi;

/***************************************************************************/

static int32_t mz_stream_ioapi_open(void *stream, const char *path, int32_t mode);
static int32_t mz_stream_ioapi_is_open(void *stream);
static int64_t mz_stream_ioapi_read(void *stream, void *buf, int64_t size);
static int64_t mz_stream_ioapi_write(void *stream, const void *buf, int64_t size);
static int64_t mz_stream_ioapi_tell(void *stream);
static int64_t mz_stream_ioapi_seek(void *stream, int64_t offset, int32_t origin);
static int32_t mz_stream_ioapi_close(void *stream);
static int32_t mz_stream_ioapi_error(void *stream);

/***************************************************************************/

static mz_stream_vtbl mz_stream_ioapi_vtbl = {mz_stream_ioapi_open,
                                              mz_stream_ioapi_is_open,
                                              mz_stream_ioapi_read,
                                              mz_stream_ioapi_write,
                                              mz_stream_ioapi_tell,
                                              mz_stream_ioapi_seek,
                                              mz_stream_ioapi_close,
                                              mz_stream_ioapi_error,
                                              mz_stream_ioapi_create,
                                              mz_stream_ioapi_delete,
                                              NULL,
                                              NULL};

/***************************************************************************/

static int32_t mz_stream_ioapi_open(void *stream, const char *path, int32_t mode) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    int32_t ioapi_mode = 0;

    if ((mode & MZ_OPEN_MODE_READWRITE) == MZ_OPEN_MODE_READ)
        ioapi_mode = ZLIB_FILEFUNC_MODE_READ;
    else if (mode & MZ_OPEN_MODE_APPEND)
        ioapi_mode = ZLIB_FILEFUNC_MODE_EXISTING;
    else if (mode & MZ_OPEN_MODE_CREATE)
        ioapi_mode = ZLIB_FILEFUNC_MODE_CREATE;
    else
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc64.zopen64_file)
        ioapi->handle = ioapi->filefunc64.zopen64_file(ioapi->filefunc64.opaque, path, ioapi_mode);
    else if (ioapi->filefunc.zopen_file)
        ioapi->handle = ioapi->filefunc.zopen_file(ioapi->filefunc.opaque, path, ioapi_mode);

    if (!ioapi->handle)
        return MZ_PARAM_ERROR;

    return MZ_OK;
}

static int32_t mz_stream_ioapi_is_open(void *stream) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    if (!ioapi->handle)
        return MZ_OPEN_ERROR;
    return MZ_OK;
}

static int64_t mz_stream_ioapi_read(void *stream, void *buf, int64_t size) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    read_file_func zread = NULL;
    void *opaque = NULL;
    unsigned long to_read;
    unsigned long bytes_read;
    int64_t total_read = 0;
    
    if (size < 0)
        return MZ_PARAM_ERROR;

    if (size == 0)
        return 0;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc64.zread_file) {
        zread = ioapi->filefunc64.zread_file;
        opaque = ioapi->filefunc64.opaque;
    } else if (ioapi->filefunc.zread_file) {
        zread = ioapi->filefunc.zread_file;
        opaque = ioapi->filefunc.opaque;
    } else
        return MZ_PARAM_ERROR;

    //Because zread expects unsigned long in size which differs on different system
    //Need to clamp existed data and feed it in chuncks
    while (total_read < size)
    {
        to_read = (size - total_read > ULONG_MAX) ? ULONG_MAX : (unsigned long) (size - total_read);
        bytes_read = zread(opaque, ioapi->handle, (uint8_t *)buf + total_read, to_read);

        if (bytes_read <= 0)
            break;

        total_read += bytes_read;

    }

    return total_read;
}

static int64_t mz_stream_ioapi_write(void *stream, const void *buf, int64_t size) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    write_file_func zwrite = NULL;
    void *opaque = NULL;
    int64_t total_written = 0;
    unsigned long to_write;
    unsigned long bytes_written;

    if (size < 0)
        return MZ_PARAM_ERROR;

    if (size == 0)
        return 0;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc64.zwrite_file) {
        zwrite = ioapi->filefunc64.zwrite_file;
        opaque = ioapi->filefunc64.opaque;
    } else if (ioapi->filefunc.zwrite_file) {
        zwrite = ioapi->filefunc.zwrite_file;
        opaque = ioapi->filefunc.opaque;
    } else
        return MZ_PARAM_ERROR;

    //Because zwrite expects unsigned long in size which differs on different system
    //Need to clamp existed data and feed it in chuncks
    while (total_written < size)
    {
        to_write = (size - total_written > ULONG_MAX) ? ULONG_MAX : (unsigned long) (size - to_write);
        bytes_written = zwrite(opaque, ioapi->handle, (const uint8_t *)buf + total_written, to_write);

        if (bytes_written <= 0)
            break;

        total_written += bytes_written;

    }

    return total_written;
}

static int64_t mz_stream_ioapi_tell(void *stream) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc64.ztell64_file)
        return ioapi->filefunc64.ztell64_file(ioapi->filefunc64.opaque, ioapi->handle);
    else if (ioapi->filefunc.ztell_file)
        return ioapi->filefunc.ztell_file(ioapi->filefunc.opaque, ioapi->handle);

    return MZ_INTERNAL_ERROR;
}

static int64_t mz_stream_ioapi_seek(void *stream, int64_t offset, int32_t origin) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc64.zseek64_file) {
        if (ioapi->filefunc64.zseek64_file(ioapi->filefunc64.opaque, ioapi->handle, offset, origin) != 0)
            return MZ_INTERNAL_ERROR;
    } else if (ioapi->filefunc.zseek_file) {
        if (offset < INT32_MIN || offset > INT32_MAX)
            return MZ_PARAM_ERROR;
        if (ioapi->filefunc.zseek_file(ioapi->filefunc.opaque, ioapi->handle, (int32_t)offset, origin) != 0)
            return MZ_INTERNAL_ERROR;
    } else
        return MZ_PARAM_ERROR;

    return MZ_OK;
}

static int32_t mz_stream_ioapi_close(void *stream) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    close_file_func zclose = NULL;
    void *opaque = NULL;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc.zclose_file) {
        zclose = ioapi->filefunc.zclose_file;
        opaque = ioapi->filefunc.opaque;
    } else if (ioapi->filefunc64.zclose_file) {
        zclose = ioapi->filefunc64.zclose_file;
        opaque = ioapi->filefunc64.opaque;
    } else
        return MZ_PARAM_ERROR;

    if (zclose(opaque, ioapi->handle) != 0)
        return MZ_CLOSE_ERROR;
    ioapi->handle = NULL;
    return MZ_OK;
}

static int32_t mz_stream_ioapi_error(void *stream) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    testerror_file_func zerror = NULL;
    void *opaque = NULL;

    if (mz_stream_ioapi_is_open(stream) != MZ_OK)
        return MZ_OPEN_ERROR;

    if (ioapi->filefunc.zerror_file) {
        zerror = ioapi->filefunc.zerror_file;
        opaque = ioapi->filefunc.opaque;
    } else if (ioapi->filefunc64.zerror_file) {
        zerror = ioapi->filefunc64.zerror_file;
        opaque = ioapi->filefunc64.opaque;
    } else
        return MZ_PARAM_ERROR;

    return zerror(opaque, ioapi->handle);
}

int32_t mz_stream_ioapi_set_filefunc(void *stream, zlib_filefunc_def *filefunc) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    memcpy(&ioapi->filefunc, filefunc, sizeof(zlib_filefunc_def));
    return MZ_OK;
}

int32_t mz_stream_ioapi_set_filefunc64(void *stream, zlib_filefunc64_def *filefunc) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)stream;
    memcpy(&ioapi->filefunc64, filefunc, sizeof(zlib_filefunc64_def));
    return MZ_OK;
}

void *mz_stream_ioapi_create(void) {
    mz_stream_ioapi *ioapi = (mz_stream_ioapi *)calloc(1, sizeof(mz_stream_ioapi));
    if (ioapi)
        ioapi->stream.vtbl = &mz_stream_ioapi_vtbl;
    return ioapi;
}

void mz_stream_ioapi_delete(void **stream) {
    mz_stream_ioapi *ioapi = NULL;
    if (!stream)
        return;
    ioapi = (mz_stream_ioapi *)*stream;
    free(ioapi);
    *stream = NULL;
}

/***************************************************************************/

void fill_fopen_filefunc(zlib_filefunc_def *pzlib_filefunc_def) {
    /* For 32-bit file support only, compile with MZ_FILE32_API */
    if (pzlib_filefunc_def)
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc_def));
}

void fill_fopen64_filefunc(zlib_filefunc64_def *pzlib_filefunc_def) {
    /* All mz_stream_os_* support large files if compilation supports it */
    if (pzlib_filefunc_def)
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc64_def));
}

void fill_win32_filefunc(zlib_filefunc_def *pzlib_filefunc_def) {
    /* Handled by mz_stream_os_win32 */
    if (pzlib_filefunc_def)
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc_def));
}

void fill_win32_filefunc64(zlib_filefunc64_def *pzlib_filefunc_def) {
    /* Automatically supported in mz_stream_os_win32 */
    if (pzlib_filefunc_def)
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc64_def));
}

void fill_win32_filefunc64A(zlib_filefunc64_def *pzlib_filefunc_def) {
    /* Automatically supported in mz_stream_os_win32 */
    if (pzlib_filefunc_def)
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc64_def));
}

/* NOTE: fill_win32_filefunc64W is no longer necessary since wide-character
   support is automatically handled by the underlying os stream. Do not
   pass wide-characters to zipOpen or unzOpen. */

void fill_memory_filefunc(zlib_filefunc_def *pzlib_filefunc_def) {
    /* Use opaque to indicate which stream interface to create */
    if (pzlib_filefunc_def) {
        memset(pzlib_filefunc_def, 0, sizeof(zlib_filefunc_def));
        pzlib_filefunc_def->opaque = mz_stream_mem_get_interface();
    }
}
