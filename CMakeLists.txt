#***************************************************************************
# Copyright:  Matthias Schmieder,
# E-Mail:     schmieder.matthias@gmail.com
# Year:       2016
#***************************************************************************
cmake_minimum_required(VERSION 2.8)

option(USE_AES "Enables building of AES library" ON)
option(USE_BZIP2 "Enables building of BZIP2 library" ON)
option(USE_LIBLZMA "Enables building of LZMA library" ON)
option(BUILD_TEST "Enables building of executables minizip and miniunz. Requires ZLIB!" ON)

# Set a consistent MACOSX_RPATH default across all CMake versions.
# When CMake 2.8.12 is required, change this default to 1.
# When CMake 3.0.0 is required, remove this block (see CMP0042).
if(NOT DEFINED CMAKE_MACOSX_RPATH)
    set(CMAKE_MACOSX_RPATH 0)
endif()

project("minizip")

# set cmake debug postfix to d
set(CMAKE_DEBUG_POSTFIX "d")

# Ensure correct version of zlib is referenced
set(ZLIB_ROOT ${DEF_ZLIB_ROOT} CACHE PATH "Parent directory of zlib installation")
find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
endif()

set(MINIZIP_SRC "mz_strm.c"
    "mz_strm_buf.c"
    "mz_strm_crypt.c"
    "mz_strm_mem.c"
    "mz_strm_posix.c"
    "mz_strm_zlib.c"
    "mz_unzip.c"
    "mz_zip.c")

set(MINIZIP_PUBLIC_HEADERS "mz_strm.h"
    "mz_strm_buf.h"
    "mz_strm_crypt.h"
    "mz_strm_mem.h"
    "mz_strm_posix.h"
    "mz_strm_zlib.h"
    "mz_unzip.h"
    "mz_zip.h")

if(WIN32)
    list(APPEND MINIZIP_SRC "mz_strm_win32.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_win32.h")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
endif()

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -O3")
    add_definitions(-D__USE_FILE_OFFSET64)
    add_definitions(-D__USE_LARGEFILE64)
    add_definitions(-D_LARGEFILE64_SOURCE)
    add_definitions(-D_FILE_OFFSET_BIT=64)
endif()

if(USE_AES)
    add_definitions(-DHAVE_AES)
    set(MINIZIP_SRC ${MINIZIP_SRC} "mz_strm_aes.c")
    set(MINIZIP_PUBLIC_HEADERS ${MINIZIP_SRC} "mz_strm_aes.h")
endif()
if(USE_BZIP2)
    add_definitions(-DHAVE_BZIP2)
    add_definitions(-DBZ_NO_STDIO)
    set(MINIZIP_SRC ${MINIZIP_SRC} "mz_strm_bzip.c")
    set(MINIZIP_PUBLIC_HEADERS ${MINIZIP_SRC} "mz_strm_bzip.h")
endif()
if(USE_LIBLZMA)
    add_definitions(-DHAVE_LZMA)
    add_definitions(-DHAVE_CONFIG_H)
    add_definitions(-DLZMA_API_STATIC)
    if(UNIX)
        add_definitions(-DMYTHREAD_POSIX)
    endif()
    set(MINIZIP_SRC ${MINIZIP_SRC} "mz_strm_lzma.c")
    set(MINIZIP_PUBLIC_HEADERS ${MINIZIP_SRC} "mz_strm_lzma.h")
endif()

if(CMAKE_C_COMPILER MATCHES ".*clang")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -msse3 -msse4.1 -maes")
endif()

include_directories(lib
                    lib/aes
                    lib/bzip2
                    lib/lzma/api)

# create minizip library
add_library(libminizip ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS})

set_target_properties(libminizip PROPERTIES PREFIX "")
target_link_libraries(libminizip ZLIB::ZLIB)

if(USE_AES)
    set(AES_SRC
        lib/aes/aescrypt.c
        lib/aes/aeskey.c
        lib/aes/aestab.c
        lib/aes/aes_ni.c
        lib/aes/fileenc.c
        lib/aes/hmac.c
        lib/aes/pwd2key.c
        lib/aes/sha1.c)

    set(AES_PUBLIC_HEADERS
        lib/aes/aes.h
        lib/aes/aes_ni.h
        lib/aes/aesopt.h
        lib/aes/aestab.h
        lib/aes/brg_endian.h
        lib/aes/brg_types.h
        lib/aes/fileenc.h
        lib/aes/hmac.h
        lib/aes/pwd2key.h
        lib/aes/sha1.h)

    add_library(aes ${AES_SRC} ${AES_PUBLIC_HEADERS})

    set_target_properties(aes PROPERTIES LINKER_LANGUAGE C)
    target_link_libraries(libminizip aes)

    install(TARGETS aes EXPORT libminizip-exports
            INCLUDES DESTINATION "lib"
            RUNTIME DESTINATION  "bin"
            LIBRARY DESTINATION  "lib"
            ARCHIVE DESTINATION  "lib")

    install(FILES ${AES_PUBLIC_HEADERS}
            DESTINATION "include/minizip")
endif()

if(USE_BZIP2)
    set(BZIP2_SRC
        lib/bzip2/blocksort.c
        lib/bzip2/bzlib.c
        lib/bzip2/compress.c
        lib/bzip2/crctable.c
        lib/bzip2/decompress.c
        lib/bzip2/huffman.c
        lib/bzip2/mk251.c
        lib/bzip2/randtable.c)

    set(BZIP2_PUBLIC_HEADERS
        lib/bzip2/bzlib.h
        lib/bzip2/bzlib_private.h)

    add_library(bzip2 ${BZIP2_SRC} ${BZIP2_PUBLIC_HEADERS})

    set_target_properties(bzip2 PROPERTIES LINKER_LANGUAGE C)
    target_link_libraries(libminizip bzip2)

    install(TARGETS bzip2 EXPORT libminizip-exports
            INCLUDES DESTINATION "lib"
            RUNTIME DESTINATION  "bin"
            LIBRARY DESTINATION  "lib"
            ARCHIVE DESTINATION  "lib")

    install(FILES ${BZIP2_PUBLIC_HEADERS}
            DESTINATION "include/minizip")
endif()

if(USE_LIBLZMA)
    set(LIBLZMA_SRC
        lib/liblzma/check/check.c
        lib/liblzma/check/crc32_fast.c
        lib/liblzma/check/crc32_table.c
        lib/liblzma/common/alone_decoder.c
        lib/liblzma/common/alone_encoder.c
        lib/liblzma/common/auto_decoder.c
        lib/liblzma/common/block_buffer_decoder.c
        lib/liblzma/common/block_buffer_encoder.c
        lib/liblzma/common/block_decoder.c
        lib/liblzma/common/block_encoder.c
        lib/liblzma/common/block_header_decoder.c
        lib/liblzma/common/block_header_encoder.c
        lib/liblzma/common/block_util.c
        lib/liblzma/common/common.c
        lib/liblzma/common/easy_buffer_encoder.c
        lib/liblzma/common/easy_decoder_memusage.c
        lib/liblzma/common/easy_encoder.c
        lib/liblzma/common/easy_encoder_memusage.c
        lib/liblzma/common/easy_preset.c
        lib/liblzma/common/filter_buffer_decoder.c
        lib/liblzma/common/filter_buffer_encoder.c
        lib/liblzma/common/filter_common.c
        lib/liblzma/common/filter_decoder.c
        lib/liblzma/common/filter_encoder.c
        lib/liblzma/common/filter_flags_decoder.c
        lib/liblzma/common/filter_flags_encoder.c
        lib/liblzma/common/hardware_cputhreads.c
        lib/liblzma/common/hardware_physmem.c
        lib/liblzma/common/index.c
        lib/liblzma/common/index_decoder.c
        lib/liblzma/common/index_encoder.c
        lib/liblzma/common/index_hash.c
        lib/liblzma/common/outqueue.c
        lib/liblzma/common/stream_buffer_decoder.c
        lib/liblzma/common/stream_buffer_encoder.c
        lib/liblzma/common/stream_decoder.c
        lib/liblzma/common/stream_encoder.c
        lib/liblzma/common/stream_encoder_mt.c
        lib/liblzma/common/stream_flags_common.c
        lib/liblzma/common/stream_flags_decoder.c
        lib/liblzma/common/stream_flags_encoder.c
        lib/liblzma/common/tuklib_cpucores.c
        lib/liblzma/common/tuklib_exit.c
        lib/liblzma/common/tuklib_mbstr_fw.c
        lib/liblzma/common/tuklib_mbstr_width.c
        lib/liblzma/common/tuklib_open_stdxxx.c
        lib/liblzma/common/tuklib_physmem.c
        lib/liblzma/common/tuklib_progname.c
        lib/liblzma/common/tuklib_progname.h
        lib/liblzma/common/vli_decoder.c
        lib/liblzma/common/vli_encoder.c
        lib/liblzma/common/vli_size.c
        lib/liblzma/lz/lz_decoder.c
        lib/liblzma/lz/lz_encoder.c
        lib/liblzma/lz/lz_encoder_mf.c
        lib/liblzma/lzma/fastpos.h
        lib/liblzma/lzma/fastpos_table.c
        lib/liblzma/lzma/lzma_decoder.c
        lib/liblzma/lzma/lzma_encoder.c
        lib/liblzma/lzma/lzma_encoder_optimum_fast.c
        lib/liblzma/lzma/lzma_encoder_optimum_normal.c
        lib/liblzma/lzma/lzma_encoder_presets.c
        lib/liblzma/rangecoder/price_table.c)

    set(LIBLZMA_PUBLIC_HEADERS
        lib/liblzma/config.h
        lib/liblzma/api/lzma.h
        lib/liblzma/api/lzma/base.h
        lib/liblzma/api/lzma/bcj.h
        lib/liblzma/api/lzma/block.h
        lib/liblzma/api/lzma/check.h
        lib/liblzma/api/lzma/container.h
        lib/liblzma/api/lzma/delta.h
        lib/liblzma/api/lzma/filter.h
        lib/liblzma/api/lzma/hardware.h
        lib/liblzma/api/lzma/index.h
        lib/liblzma/api/lzma/index_hash.h
        lib/liblzma/api/lzma/lzma12.h
        lib/liblzma/api/lzma/stream_flags.h
        lib/liblzma/api/lzma/version.h
        lib/liblzma/api/lzma/vli.h
        lib/liblzma/check/check.h
        lib/liblzma/check/crc32_table_be.h
        lib/liblzma/check/crc32_table_le.h
        lib/liblzma/check/crc_macros.h
        lib/liblzma/common/alone_decoder.h
        lib/liblzma/common/block_buffer_encoder.h
        lib/liblzma/common/block_decoder.h
        lib/liblzma/common/block_encoder.h
        lib/liblzma/common/common.h
        lib/liblzma/common/easy_preset.h
        lib/liblzma/common/filter_common.h
        lib/liblzma/common/filter_decoder.h
        lib/liblzma/common/filter_encoder.h
        lib/liblzma/common/index.h
        lib/liblzma/common/index_encoder.h
        lib/liblzma/common/memcmplen.h
        lib/liblzma/common/mythread.h
        lib/liblzma/common/outqueue.h
        lib/liblzma/common/stream_decoder.h
        lib/liblzma/common/stream_flags_common.h
        lib/liblzma/common/sysdefs.h
        lib/liblzma/common/tuklib_common.h
        lib/liblzma/common/tuklib_config.h
        lib/liblzma/common/tuklib_cpucores.h
        lib/liblzma/common/tuklib_exit.h
        lib/liblzma/common/tuklib_gettext.h
        lib/liblzma/common/tuklib_integer.h
        lib/liblzma/common/tuklib_mbstr.h
        lib/liblzma/common/tuklib_open_stdxxx.h
        lib/liblzma/common/tuklib_physmem.h
        lib/liblzma/lz/lz_decoder.h
        lib/liblzma/lz/lz_encoder.h
        lib/liblzma/lz/lz_encoder_hash.h
        lib/liblzma/lz/lz_encoder_hash_table.h
        lib/liblzma/lzma/lzma2_encoder.h
        lib/liblzma/lzma/lzma_common.h
        lib/liblzma/lzma/lzma_decoder.h
        lib/liblzma/lzma/lzma_encoder.h
        lib/liblzma/lzma/lzma_encoder_private.h
        lib/liblzma/rangecoder/price.h
        lib/liblzma/rangecoder/range_common.h
        lib/liblzma/rangecoder/range_decoder.h
        lib/liblzma/rangecoder/range_encoder.h)

    include_directories(lib/liblzma
                        lib/liblzma/api
                        lib/liblzma/check
                        lib/liblzma/common
                        lib/liblzma/lz
                        lib/liblzma/lzma
                        lib/liblzma/rangecoder)

    add_library(liblzma ${LIBLZMA_SRC} ${LIBLZMA_PUBLIC_HEADERS})

    set_target_properties(liblzma PROPERTIES LINKER_LANGUAGE C)
    set_target_properties(liblzma PROPERTIES PREFIX "")

    target_link_libraries(libminizip liblzma)

    install(TARGETS liblzma EXPORT libminizip-exports
            INCLUDES DESTINATION "lib"
            RUNTIME DESTINATION  "bin"
            LIBRARY DESTINATION  "lib"
            ARCHIVE DESTINATION  "lib")

    install(FILES ${LIBLZMA_PUBLIC_HEADERS}
            DESTINATION "include/minizip")
endif()

install(TARGETS libminizip EXPORT libminizip-exports
        INCLUDES DESTINATION "include"
        RUNTIME DESTINATION "bin"
        LIBRARY DESTINATION "lib"
        ARCHIVE DESTINATION "lib")

install(EXPORT libminizip-exports
        DESTINATION "cmake"
        NAMESPACE "MINIZIP::")

install(FILES ${MINIZIP_PUBLIC_HEADERS}
        DESTINATION "include/minizip")

#if(BUILD_TEST)
    add_executable(miniunz miniunz.c)
    target_link_libraries(miniunz libminizip)

    add_executable(minizip minizip.c)
    target_link_libraries(minizip libminizip)

    install(TARGETS miniunz minizip
            RUNTIME DESTINATION "bin")
#endif()
