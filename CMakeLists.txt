#***************************************************************************
# Copyright (C) 2017-2020 Nathan Moinvaziri
#                         https://github.com/nmoinvaz/minizip
# Copyright (C)      2016 Matthias Schmieder
#                         schmieder.matthias@gmail.com
#***************************************************************************

cmake_minimum_required(VERSION 3.0.2)

message(STATUS "Using CMake version ${CMAKE_VERSION}")

option(MZ_COMPAT "Enables compatibility layer" ON)
option(MZ_ZLIB "Enables ZLIB compression" ON)
option(MZ_BZIP2 "Enables BZIP2 compression" ON)
option(MZ_LZMA "Enables LZMA compression" ON)
option(MZ_PKCRYPT "Enables PKWARE traditional encryption" ON)
option(MZ_WZAES "Enables WinZIP AES encryption" ON)
option(MZ_LIBCOMP "Enables Apple compression" OFF)
option(MZ_OPENSSL "Enables OpenSSL for encryption" OFF)
option(MZ_BRG "Enables Brian Gladman's encryption library" OFF)
option(MZ_SIGNING "Enables zip signing support" ON)
option(MZ_COMPRESS_ONLY "Only support compression" OFF)
option(MZ_DECOMPRESS_ONLY "Only support decompression" OFF)
option(MZ_BUILD_TEST "Builds minizip test executable" OFF)
option(MZ_BUILD_UNIT_TEST "Builds minizip unit test project" OFF)
option(MZ_BUILD_FUZZ_TEST "Builds minizip fuzzer executables" OFF)
option(MZ_CODE_COVERAGE "Builds with code coverage flags" OFF)
set(MZ_PROJECT_SUFFIX "" CACHE STRING "Project name suffix for package managers")

if(POLICY CMP0074)
    cmake_policy(SET CMP0074 OLD)
endif()
# ZLIB_ROOT - Parent directory of zlib installation
# BZIP2_ROOT - Parent directory of BZip2 installation
# OPENSSL_ROOT - Parent directory of OpenSSL installation

enable_language(C)

# Minizip library version
set(VERSION "2.9.3")

# Minizip api version
set(SOVERSION "2.5")

include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)
include(GNUInstallDirs)
include(ExternalProject)
include(FeatureSummary)

set(INSTALL_BIN_DIR ${CMAKE_INSTALL_FULL_BINDIR} CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR ${CMAKE_INSTALL_FULL_LIBDIR} CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR ${CMAKE_INSTALL_FULL_INCLUDEDIR} CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR ${CMAKE_INSTALL_FULL_MANDIR} CACHE PATH "Installation directory for manual pages")

set(STDLIB_DEF)
set(MINIZIP_DEF)
set(MINIZIP_INC)
set(PC_PRIVATE_LIBS)

# Check if zlib installation is present
if(MZ_ZLIB AND NOT MZ_LIBCOMP)
    find_package(ZLIB)
    if(ZLIB_FOUND)
        message(STATUS "Using ZLIB ${ZLIB_VERSION_STRING}")
        list(APPEND MINIZIP_INC ${ZLIB_INCLUDE_DIRS})
        set(PC_PRIVATE_LIBS " -lz")
    else()
        if (NOT ZLIB_TAG)
            set(ZLIB_TAG master)
        endif()
        if (NOT ZLIB_REPOSITORY)
            set(ZLIB_REPOSITORY https://github.com/madler/zlib)
        endif()

        message(STATUS "Using ZLIB ${ZLIB_REPOSITORY} ${ZLIB_TAG}")

        set(ZLIB_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/zlib)
        set(ZLIB_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install/zlib)
        set(ZLIB_INCLUDE_DIRS ${ZLIB_INSTALL_DIR}/include)

        if(WIN32)
            set(ZLIB_LIBRARIES
                ${ZLIB_INSTALL_DIR}/lib/zlibstatic$<$<CONFIG:Debug>:d>.lib)
            set(ZLIB_BYPRODUCTS
                ${ZLIB_INSTALL_DIR}/lib/zlibstatic.lib ${ZLIB_INSTALL_DIR}/lib/zlibstaticd.lib)
        else()
            set(ZLIB_LIBRARIES
                ${ZLIB_INSTALL_DIR}/lib/libz.a)
            set(ZLIB_BYPRODUCTS
                ${ZLIB_INSTALL_DIR}/lib/libz.a)
        endif()

        # Build args variable based on cache variables
        unset(CMAKE_ARGS)
        get_cmake_property(CACHE_VARS CACHE_VARIABLES)
        foreach(CACHE_VAR ${CACHE_VARS})
            get_property(CACHE_VAR_HELPSTRING CACHE ${CACHE_VAR} PROPERTY HELPSTRING)
            if(CACHE_VAR_HELPSTRING STREQUAL "No help, variable specified on the command line.")
                get_property(CACHE_VAR_TYPE CACHE ${CACHE_VAR} PROPERTY TYPE)
                if(CACHE_VAR_TYPE STREQUAL "UNINITIALIZED")
                    set(CACHE_VAR_TYPE)
                else()
                    set(CACHE_VAR_TYPE :${CACHE_VAR_TYPE})
                endif()
                if (NOT CACHE_VAR MATCHES "^MZ_")
                    list(APPEND CMAKE_ARGS "-D${CACHE_VAR}${CACHE_VAR_TYPE}=${${CACHE_VAR}}")
                endif()
            endif()
        endforeach()

        ExternalProject_Add(zlib
            PREFIX zlib
            GIT_REPOSITORY ${ZLIB_REPOSITORY}
            GIT_TAG ${ZLIB_TAG}
            SOURCE_DIR ${ZLIB_SOURCE_DIR}
            BUILD_IN_SOURCE 1
            INSTALL_DIR ${ZLIB_INSTALL_DIR}
            BUILD_BYPRODUCTS ${ZLIB_BYPRODUCTS}
            UPDATE_COMMAND ""
            CMAKE_ARGS "${CMAKE_ARGS};-DCMAKE_INSTALL_PREFIX:STRING=${ZLIB_INSTALL_DIR}")

        list(APPEND MINIZIP_INC ${ZLIB_INCLUDE_DIRS})
    endif()
endif()

# Check if bzip2 installation is present
if(MZ_BZIP2)
    find_package(BZip2)
    if(BZIP2_FOUND)
        message(STATUS "Using BZIP2 ${BZIP2_VERSION_STRING}")
        list(APPEND MINIZIP_INC ${BZIP2_INCLUDE_DIRS})
        list(APPEND MINIZIP_DEF -DHAVE_BZIP2)
        set(PC_PRIVATE_LIBS "${PC_PRIVATE_LIBS} -lbzip2")
    endif()
endif()

# Check to see if openssl installation is present
if(MZ_OPENSSL)
    find_package(OpenSSL)
    if (OPENSSL_FOUND)
        message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

        list(APPEND MINIZIP_INC ${OPENSSL_INCLUDE_DIR})
        if(OPENSSL_INCLUDE_DIRS)
            list(APPEND MINIZIP_INC ${OPENSSL_INCLUDE_DIRS})
        endif()
    endif()
endif()

# Check for system includes
check_include_file(stdint.h   HAVE_STDINT_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)

if(HAVE_STDINT_H)
    list(APPEND STDLIB_DEF -DHAVE_STDINT_H)
endif()
if(HAVE_INTTYPES_H)
    list(APPEND STDLIB_DEF -DHAVE_INTTYPES_H)
endif()

# Check for large file support
check_type_size(off64_t OFF64_T)
if(HAVE_OFF64_T)
    list(APPEND STDLIB_DEF -D__USE_FILE_OFFSET64)
    list(APPEND STDLIB_DEF -D__USE_LARGEFILE64)
    list(APPEND STDLIB_DEF -D_LARGEFILE64_SOURCE)
    list(APPEND STDLIB_DEF -D_FILE_OFFSET_BITS=64)
endif()
# Check for fseeko support
check_function_exists(fseeko HAVE_FSEEKO)
if(NOT HAVE_FSEEKO)
    list(APPEND STDLIB_DEF -DNO_FSEEKO)
endif()

# Enable compiler warnings
if(MSVC)
    add_compile_options(/W3)
else()
    add_compile_options(-W -Wall)
endif()
# Enable x86 optimizations if supported
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    include(CheckCCompilerFlag)

    macro(enable_option_if_supported option variable)
        check_c_compiler_flag(
            "-Werror=unused-command-line-argument ${option}" ${variable})
        if(${variable})
            add_compile_options("$<$<CONFIG:Release>:${option}>")
        endif()
    endmacro()

    enable_option_if_supported(-msse3 check_opt_sse3)
    enable_option_if_supported(-msse4.1 check_opt_sse41)
    enable_option_if_supported(-maes check_opt_aes)
endif()
# Set compiler options
if(MZ_CODE_COVERAGE)
    if(NOT MSVC)
        message(STATUS "Code coverage enabled")
        add_compile_options(-O0 -g -fprofile-arcs -ftest-coverage)
        if(CMAKE_C_COMPILER_ID MATCHES "(Apple)?[Cc]lang")
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
        elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
            link_libraries(gcov)
        endif()
    else()
        set(MZ_CODE_COVERAGE OFF)
    endif()
else()
    if(MSVC)
        add_compile_options(
            $<$<CONFIG:Debug>:/Zi>
            $<$<CONFIG:Debug>:/Od>
            $<$<CONFIG:Release>:/Ox>
            $<$<CONFIG:Release>:/Os>)
    else()
        add_compile_options(
            $<$<CONFIG:Debug>:-g>
            $<$<CONFIG:Release>:-Os>)
    endif()
endif()

# Initial source files
set(MINIZIP_SRC
    mz_crypt.c
    mz_os.c
    mz_strm.c
    mz_strm_buf.c
    mz_strm_mem.c
    mz_strm_split.c
    mz_zip.c
    mz_zip_rw.c)

# Initial header files
set(MINIZIP_PUBLIC_HEADERS
    mz.h
    mz_os.h
    mz_crypt.h
    mz_strm.h
    mz_strm_buf.h
    mz_strm_mem.h
    mz_strm_split.h
    mz_strm_os.h
    mz_zip.h
    mz_zip_rw.h)

# Windows specific
if(WIN32)
    list(APPEND MINIZIP_DEF -D_CRT_SECURE_NO_DEPRECATE)

    list(APPEND MINIZIP_SRC "mz_os_win32.c" "mz_strm_os_win32.c")
    if (MZ_PKCRYPT OR MZ_WZAES)
        if (NOT MZ_OPENSSL AND NOT OPENSSL_FOUND AND NOT MZ_BRG)
            list(APPEND MINIZIP_SRC "mz_crypt_win32.c")
        endif()
    endif()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
    list(APPEND MINIZIP_DEF -DMZ_WINRT_API)
endif()

# Unix specific
if(UNIX)
    list(APPEND STDLIB_DEF -D_POSIX_C_SOURCE=200112L)
    list(APPEND MINIZIP_SRC "mz_os_posix.c" "mz_strm_os_posix.c")

    if ((MZ_PKCRYPT OR MZ_WZAES) AND NOT (MZ_OPENSSL AND OPENSSL_FOUND))

        if (APPLE AND NOT MZ_BRG)
            check_include_file(CommonCrypto/CommonCrypto.h COMMONCRYPTO_FOUND)
            if (COMMONCRYPTO_FOUND)
                list(APPEND MINIZIP_SRC "mz_crypt_apple.c")
            else()
                message(STATUS "CommonCrypto not found, using BRG instead")
                set(MZ_BRG TRUE)
            endif()
        else()
            set(MZ_BRG TRUE)
        endif()

        # Check to see which random generation functions we have
        check_symbol_exists("getrandom" "sys/random.h" HAVE_GETRANDOM)
        if (HAVE_GETRANDOM)
            list(APPEND MINIZIP_DEF -DHAVE_GETRANDOM)
        endif()
        check_symbol_exists("arc4random_buf" "stdlib.h" HAVE_ARC4RANDOM_BUF)
        if (HAVE_ARC4RANDOM_BUF)
            list(APPEND MINIZIP_DEF -DHAVE_ARC4RANDOM_BUF)
        else()
            check_symbol_exists("arc4random" "stdlib.h" HAVE_ARC4RANDOM)
            if (HAVE_ARC4RANDOM)
                list(APPEND MINIZIP_DEF -DHAVE_ARC4RANDOM)
            endif()
        endif()

        if(NOT HAVE_ARC4RANDOM_BUF)
            find_package(PkgConfig REQUIRED)

            pkg_check_modules(LIBBSD libbsd)
            if (LIBBSD_FOUND)
                check_library_exists("${LIBBSD_LIBRARIES}" "arc4random_buf"
                    "${LIBBSD_LIBRARY_DIRS}" HAVE_LIBBSD_ARC4RANDOM_BUF)
                if (HAVE_LIBBSD_ARC4RANDOM_BUF)
                    list(APPEND MINIZIP_DEF -DHAVE_LIBBSD)
                    list(APPEND MINIZIP_DEF -DHAVE_ARC4RANDOM_BUF)
                    list(APPEND MINIZIP_INC ${LIBBSD_INCLUDE_DIRS})
                    link_directories(${LIBBSD_LIBRARY_DIRS})
                endif()
            endif()
        endif()
    endif()

    # Iconv is only necessary when it is not already built-in
    # FindIconv requires cmake 3.11 or higher
    find_package(Iconv QUIET)
    if (Iconv_FOUND)
        message(STATUS "Using Iconv")
        list(APPEND MINIZIP_DEF -DHAVE_ICONV)
        list(APPEND MINIZIP_INC ${Iconv_INCLUDE_DIRS})
        set(PC_PRIVATE_LIBS "${PC_PRIVATE_LIBS} -liconv")
    else()
        message(WARNING "Limited encoding support due to missing iconv")
    endif()
endif()

# Include compatibility layer
if(MZ_COMPAT)
    list(APPEND MINIZIP_SRC "mz_compat.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_compat.h")

    set(COMPAT_HEADER "\
/* file.h -- Compatibility layer shim\n\
   part of the MiniZip project\n\n\
   This program is distributed under the terms of the same license as zlib.\n\
   See the accompanying LICENSE file for the full text of the license.\n\
*/\n\n\
#ifndef MZ_COMPAT_FILE\n\
#define MZ_COMPAT_FILE\n\n\
#include \"mz_compat.h\"\n\n\
#endif\n")

    string(REPLACE "file.h" "zip.h" ZIP_COMPAT_HEADER ${COMPAT_HEADER})
    string(REPLACE "MZ_COMPAT_FILE" "MZ_COMPAT_ZIP" ZIP_COMPAT_HEADER ${ZIP_COMPAT_HEADER})
    file(WRITE "zip.h" ${ZIP_COMPAT_HEADER})
    list(APPEND MINIZIP_PUBLIC_HEADERS "zip.h")

    string(REPLACE "file.h" "unzip.h" UNZIP_COMPAT_HEADER ${COMPAT_HEADER})
    string(REPLACE "MZ_COMPAT_FILE" "MZ_COMPAT_UNZIP" UNZIP_COMPAT_HEADER ${UNZIP_COMPAT_HEADER})
    file(WRITE "unzip.h" ${UNZIP_COMPAT_HEADER})
    list(APPEND MINIZIP_PUBLIC_HEADERS "unzip.h")

    if(MZ_COMPAT_VERSION)
        list(APPEND MINIZIP_DEF -DMZ_COMPAT_VERSION=${MZ_COMPAT_VERSION})
    endif()
endif()

# Setup predefined macros
if(MZ_COMPRESS_ONLY)
    list(APPEND MINIZIP_DEF -DMZ_ZIP_NO_DECOMPRESSION)
endif()
if(MZ_DECOMPRESS_ONLY)
    list(APPEND MINIZIP_DEF -DMZ_ZIP_NO_COMPRESSION)
endif()
if(NOT MZ_PKCRYPT AND NOT MZ_WZAES)
    list(APPEND MINIZIP_DEF -DMZ_ZIP_NO_ENCRYPTION)
    message(STATUS "Signing not supported when encryption is disabled")
    set(MZ_SIGNING OFF)
endif()
if(MZ_BRG OR (MZ_OPENSSL AND NOT OPENSSL_FOUND))
    message(STATUS "Signing not supported with current configuration")
    set(MZ_SIGNING OFF)
endif()
if(MZ_SIGNING)
    list(APPEND MINIZIP_DEF -DMZ_ZIP_SIGNING)
endif()

# Include PKCRYPT
if(MZ_PKCRYPT)
    list(APPEND MINIZIP_DEF -DHAVE_PKCRYPT)

    list(APPEND MINIZIP_SRC "mz_strm_pkcrypt.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_pkcrypt.h")
endif()

# Include WinZIP AES
if(MZ_WZAES)
    list(APPEND MINIZIP_DEF -DHAVE_WZAES)

    list(APPEND MINIZIP_SRC "mz_strm_wzaes.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_wzaes.h")
endif()

# Include BRG
if(MZ_BRG)
    list(APPEND MINIZIP_SRC "mz_crypt_brg.c")

    set(BRG_SRC
        lib/brg/aescrypt.c
        lib/brg/aeskey.c
        lib/brg/aestab.c
        lib/brg/hmac.c
        lib/brg/sha1.c
        lib/brg/sha2.c)

    set(BRG_PUBLIC_HEADERS
        lib/brg/aes.h
        lib/brg/aesopt.h
        lib/brg/aestab.h
        lib/brg/brg_endian.h
        lib/brg/brg_types.h
        lib/brg/hmac.h
        lib/brg/sha1.h
        lib/brg/sha2.h)

    list(APPEND MINIZIP_INC lib/brg)

    source_group("BRG" FILES ${BRG_SRC} ${BRG_PUBLIC_HEADERS})
endif()

# Include OpenSSL
if(MZ_OPENSSL AND OPENSSL_FOUND)
    list(APPEND MINIZIP_SRC "mz_crypt_openssl.c")
endif()

# Include ZLIB
if(MZ_ZLIB)
    if(MZ_LIBCOMP)
        list(APPEND MINIZIP_DEF -DHAVE_LIBCOMP)

        list(APPEND MINIZIP_SRC "mz_strm_libcomp.c")
        list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_libcomp.h")
    else()
        list(APPEND MINIZIP_DEF -DHAVE_ZLIB)

        if(ZLIB_COMPAT)
            list(APPEND MINIZIP_DEF -DZLIB_COMPAT)
        endif()

        list(APPEND MINIZIP_SRC "mz_strm_zlib.c")
        list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_zlib.h")
    endif()
endif()

# Include BZIP2
if(MZ_BZIP2)
    list(APPEND MINIZIP_DEF -DHAVE_BZIP2)

    list(APPEND MINIZIP_SRC "mz_strm_bzip.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_bzip.h")

    if(NOT BZIP2_FOUND)
        list(APPEND MINIZIP_DEF -DBZ_NO_STDIO)

        set(BZIP2_SRC
            lib/bzip2/blocksort.c
            lib/bzip2/bzlib.c
            lib/bzip2/compress.c
            lib/bzip2/crctable.c
            lib/bzip2/decompress.c
            lib/bzip2/huffman.c
            lib/bzip2/randtable.c)

        set(BZIP2_PUBLIC_HEADERS
            lib/bzip2/bzlib.h
            lib/bzip2/bzlib_private.h)

        list(APPEND MINIZIP_INC lib/bzip2)

        source_group("BZip2" FILES ${BZIP2_SRC} ${BZIP2_PUBLIC_HEADERS})
    endif()
endif()

# Include LZMA
if(MZ_LZMA)
    check_include_file(limits.h     HAVE_LIMITS_H)
    check_include_file(string.h     HAVE_STRING_H)
    check_include_file(strings.h    HAVE_STRINGS_H)
    check_include_file(memory.h     HAVE_MEMORY_H)
    check_include_file(stdbool.h    HAVE_STDBOOL_H)
    check_include_file(immintrin.h  HAVE_IMMINTRIN_H)

    list(APPEND MINIZIP_DEF -DHAVE_CONFIG_H)

    if(HAVE_LIMITS_H)
        list(APPEND MINIZIP_DEF -DHAVE_LIMITS_H)
    endif()
    if(HAVE_STRING_H)
        list(APPEND MINIZIP_DEF -DHAVE_STRING_H)
    endif()
    if(HAVE_STRINGS_H)
        list(APPEND MINIZIP_DEF -DHAVE_STRINGS_H)
    endif()
    if(HAVE_MEMORY_H)
        list(APPEND MINIZIP_DEF -DHAVE_MEMORY_H)
    endif()
    if(HAVE_STDBOOL_H)
        list(APPEND MINIZIP_DEF -DHAVE_STDBOOL_H)
    endif()
    if(HAVE_IMMINTRIN_H)
        list(APPEND MINIZIP_DEF -DHAVE_IMMINTRIN_H)
    endif()

    list(APPEND MINIZIP_DEF -DHAVE_LZMA)
    list(APPEND MINIZIP_DEF -DLZMA_API_STATIC)

    list(APPEND MINIZIP_SRC "mz_strm_lzma.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_lzma.h")

    set(LZMA_CHECK_SRC
        lib/liblzma/check/check.c
        lib/liblzma/check/crc32_fast.c
        lib/liblzma/check/crc32_table.c)
    set(LZMA_COMMON_SRC
        lib/liblzma/common/alone_decoder.c
        lib/liblzma/common/alone_encoder.c
        lib/liblzma/common/common.c
        lib/liblzma/common/filter_encoder.c)
    set(LZMA_LZ_SRC
        lib/liblzma/lz/lz_decoder.c
        lib/liblzma/lz/lz_encoder.c
        lib/liblzma/lz/lz_encoder_mf.c)
    set(LZMA_LZMA_SRC
        lib/liblzma/lzma/fastpos.h
        lib/liblzma/lzma/fastpos_table.c
        lib/liblzma/lzma/lzma_decoder.c
        lib/liblzma/lzma/lzma_encoder.c
        lib/liblzma/lzma/lzma_encoder_optimum_fast.c
        lib/liblzma/lzma/lzma_encoder_optimum_normal.c
        lib/liblzma/lzma/lzma_encoder_presets.c)
    set(LZMA_RANGECODER_SRC
        lib/liblzma/rangecoder/price_table.c)

    set(LZMA_CONFIG_HEADERS
        lib/liblzma/config.h)
    set(LZMA_API_HEADERS
        lib/liblzma/api/lzma.h
        lib/liblzma/api/lzma/base.h
        lib/liblzma/api/lzma/check.h
        lib/liblzma/api/lzma/container.h
        lib/liblzma/api/lzma/filter.h
        lib/liblzma/api/lzma/lzma12.h
        lib/liblzma/api/lzma/version.h
        lib/liblzma/api/lzma/vli.h)
    set(LZMA_CHECK_HEADERS
        lib/liblzma/check/check.h
        lib/liblzma/check/crc32_table_be.h
        lib/liblzma/check/crc32_table_le.h
        lib/liblzma/check/crc_macros.h)
    set(LZMA_COMMON_HEADERS
        lib/liblzma/common/alone_decoder.h
        lib/liblzma/common/common.h
        lib/liblzma/common/filter_encoder.h
        lib/liblzma/common/index.h
        lib/liblzma/common/memcmplen.h
        lib/liblzma/common/sysdefs.h
        lib/liblzma/common/tuklib_common.h
        lib/liblzma/common/tuklib_config.h
        lib/liblzma/common/tuklib_integer.h)
    set(LZMA_LZ_HEADERS
        lib/liblzma/lz/lz_decoder.h
        lib/liblzma/lz/lz_encoder.h
        lib/liblzma/lz/lz_encoder_hash.h
        lib/liblzma/lz/lz_encoder_hash_table.h)
    set(LZMA_LZMA_HEADERS
        lib/liblzma/lzma/lzma2_encoder.h
        lib/liblzma/lzma/lzma_common.h
        lib/liblzma/lzma/lzma_decoder.h
        lib/liblzma/lzma/lzma_encoder.h
        lib/liblzma/lzma/lzma_encoder_private.h)
    set(LZMA_RANGECODER_HEADERS
        lib/liblzma/rangecoder/price.h
        lib/liblzma/rangecoder/range_common.h
        lib/liblzma/rangecoder/range_decoder.h
        lib/liblzma/rangecoder/range_encoder.h)

    set(LZMA_PUBLIC_HEADERS
        ${LZMA_CONFIG_HEADERS}
        ${LZMA_API_HEADERS}
        ${LZMA_CHECK_HEADERS}
        ${LZMA_COMMON_HEADERS}
        ${LZMA_LZ_HEADERS}
        ${LZMA_LZMA_HEADERS}
        ${LZMA_RANGECODER_HEADERS})

    set(LZMA_SRC
        ${LZMA_CHECK_SRC}
        ${LZMA_COMMON_SRC}
        ${LZMA_LZ_SRC}
        ${LZMA_LZMA_SRC}
        ${LZMA_RANGECODER_SRC})

    list(APPEND MINIZIP_INC lib/liblzma
                        lib/liblzma/api
                        lib/liblzma/check
                        lib/liblzma/common
                        lib/liblzma/lz
                        lib/liblzma/lzma
                        lib/liblzma/rangecoder)

    source_group("LZMA" FILES ${LZMA_CONFIG_HEADERS})
    source_group("LZMA\\API" FILES ${LZMA_API_HEADERS})
    source_group("LZMA\\Check" FILES ${LZMA_CHECK_SRC} ${LZMA_CHECK_HEADERS})
    source_group("LZMA\\Common" FILES ${LZMA_COMMON_SRC} ${LZMA_COMMON_HEADERS})
    source_group("LZMA\\LZ" FILES ${LZMA_LZ_SRC} ${LZMA_LZ_HEADERS})
    source_group("LZMA\\LZMA" FILES ${LZMA_LZMA_SRC} ${LZMA_LZMA_HEADERS})
    source_group("LZMA\\RangeCoder" FILES ${LZMA_RANGECODER_SRC} ${LZMA_RANGECODER_HEADERS})
endif()

macro(mz_configure_target target)
    target_compile_definitions(${target} PRIVATE ${STDLIB_DEF})
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(MZ_CODE_COVERAGE)
        set_target_properties(${target} PROPERTIES
            GCC_INSTRUMENT_PROGRAM_FLOW_ARCS YES
            GCC_GENERATE_TEST_COVERAGE_FILES YES)
    endif()
endmacro()

# Create minizip library
source_group("Minizip" FILES ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS})

project(minizip${MZ_PROJECT_SUFFIX} VERSION ${VERSION})

if(NOT ${MZ_PROJECT_SUFFIX} STREQUAL "")
    message(STATUS "Project configured as ${PROJECT_NAME}")
endif()

set(MINIZIP_PC ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc)
configure_file(minizip.pc.cmakein ${MINIZIP_PC} @ONLY)

set(INSTALL_CMAKE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/cmake/${PROJECT_NAME}"
    CACHE PATH "Installation directory for cmake files.")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig"
    CACHE PATH "Installation directory for pkgconfig (.pc) files")

add_library(${PROJECT_NAME}
                ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS}
                ${BRG_SRC} ${BRG_PUBLIC_HEADERS}
                ${BZIP2_SRC} ${BZIP2_PUBLIC_HEADERS}
                ${LZMA_SRC} ${LZMA_PUBLIC_HEADERS})

mz_configure_target(${PROJECT_NAME})

set_target_properties(${PROJECT_NAME} PROPERTIES
                        VERSION ${VERSION}
                        SOVERSION ${SOVERSION}
                        LINKER_LANGUAGE C
                        DEFINE_SYMBOL "MZ_EXPORTS")

if(WIN32)
    # VS debugger has problems when executable and static library are named the same
    set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME lib${PROJECT_NAME})
endif()
if(NOT RISCOS)
    set_target_properties(${PROJECT_NAME} PROPERTIES POSITION_INDEPENDENT_CODE 1)
endif()
if(MZ_LZMA)
    set_target_properties(${PROJECT_NAME} PROPERTIES C_STANDARD 99)
endif()

target_include_directories(${PROJECT_NAME} PRIVATE ${MINIZIP_INC})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${MINIZIP_DEF})

# Link with external libraries
if(MZ_ZLIB AND NOT MZ_LIBCOMP)
    target_link_libraries(${PROJECT_NAME} ${ZLIB_LIBRARIES})
    if(NOT ZLIB_FOUND)
        add_dependencies(${PROJECT_NAME} zlib)
    endif()
endif()
if(MZ_BZIP2 AND BZIP2_FOUND)
    target_link_libraries(${PROJECT_NAME} ${BZIP2_LIBRARIES})
endif()
if(MZ_LIBCOMP)
    target_link_libraries(${PROJECT_NAME} compression)
endif()
if(Iconv_FOUND AND NOT Iconv_IS_BUILT_IN)
    target_link_libraries(${PROJECT_NAME} ${Iconv_LIBRARIES})
endif()
if(MZ_OPENSSL AND OPENSSL_FOUND)
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
elseif(UNIX)
    if(APPLE AND NOT MZ_BRG)
        message(STATUS "Using CoreFoundation Framework")
        find_library(COREFOUNDATION_LIBRARY CoreFoundation)
        target_link_libraries(${PROJECT_NAME} ${COREFOUNDATION_LIBRARY})
        message(STATUS "Using Security Framework")
        find_library(SECURITY_LIBRARY Security)
        target_link_libraries(${PROJECT_NAME} ${SECURITY_LIBRARY})
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks")
    else()
        target_link_libraries(${PROJECT_NAME} ${LIBBSD_LIBRARIES})
    endif()
elseif(WIN32)
    if((MZ_PKCRYPT OR MZ_WZAES) AND NOT MZ_BRG)
        # GCC doesn't support #pragma lib
        if(CMAKE_C_COMPILER_ID MATCHES "GNU")
            target_link_libraries(${PROJECT_NAME} crypt32.lib)
        endif()
    endif()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC $<INSTALL_INTERFACE:${INSTALL_INC_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>)

# Install files
if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
    install(TARGETS ${PROJECT_NAME} EXPORT ${PROJECT_NAME}
            INCLUDES DESTINATION "${INSTALL_INC_DIR}"
            RUNTIME DESTINATION "${INSTALL_BIN_DIR}"
            ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
            LIBRARY DESTINATION "${INSTALL_LIB_DIR}")
    install(EXPORT ${PROJECT_NAME}
            DESTINATION "${INSTALL_CMAKE_DIR}"
            NAMESPACE "MINIZIP::")

    # Create and install CMake package config version file to allow find_package()
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/minizipConfigVersion.cmake
        COMPATIBILITY SameMajorVersion)

    file(WRITE minizipConfig.cmake.in "@PACKAGE_INIT@")

    # Create config for find_package()
    configure_package_config_file(minizipConfig.cmake.in minizipConfig.cmake
        INSTALL_DESTINATION "${INSTALL_CMAKE_DIR}")

    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/minizipConfigVersion.cmake
                  ${CMAKE_CURRENT_BINARY_DIR}/minizipConfig.cmake
            DESTINATION "${INSTALL_CMAKE_DIR}")
endif()
if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL)
    install(FILES ${MINIZIP_PUBLIC_HEADERS} DESTINATION "${INSTALL_INC_DIR}")
endif()
if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL)
    install(FILES ${MINIZIP_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif()

# Build test executables
if(MZ_BUILD_TEST)
    if(MZ_ZLIB AND NOT MZ_LIBCOMP)
        add_executable(minigzip_cmd "minigzip.c")
        mz_configure_target(minigzip_cmd)
        set_target_properties(minigzip_cmd PROPERTIES OUTPUT_NAME minigzip)
        target_compile_definitions(minigzip_cmd PRIVATE ${MINIZIP_DEF})
        target_link_libraries(minigzip_cmd ${PROJECT_NAME})

        if(NOT SKIP_INSTALL_BINARIES AND NOT SKIP_INSTALL_ALL)
            install(TARGETS minigzip_cmd RUNTIME DESTINATION "bin")
        endif()
    endif()

    add_executable(minizip_cmd "minizip.c")
    mz_configure_target(minizip_cmd)
    set_target_properties(minizip_cmd PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
    target_compile_definitions(minizip_cmd PRIVATE ${MINIZIP_DEF})
    target_link_libraries(minizip_cmd ${PROJECT_NAME})

    if(NOT SKIP_INSTALL_BINARIES AND NOT SKIP_INSTALL_ALL)
        install(TARGETS minizip_cmd RUNTIME DESTINATION "bin")
    endif()

    add_executable(test_cmd "test/test.c" "test/test.h")
    mz_configure_target(test_cmd)
    target_compile_definitions(test_cmd PRIVATE ${MINIZIP_DEF})
    if(MZ_COMPAT)
        target_compile_definitions(test_cmd PRIVATE -DHAVE_COMPAT)
    endif()
    target_link_libraries(test_cmd ${PROJECT_NAME})
endif()

if(MZ_BUILD_TEST AND MZ_BUILD_UNIT_TEST)
    enable_testing()

    add_test(NAME test_cmd COMMAND test_cmd WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

    function(create_compress_tests EXTRA_NAME EXTRA_ARGS)
        if(MZ_DECOMPRESS_ONLY)
            return()
        endif()
        list(FIND EXTRA_ARGS "-z" ZIPCD_IDX)
        if(${ZIPCD_IDX} EQUAL -1)
            set(COMPRESS_METHOD_NAMES "raw")
            set(COMPRESS_METHOD_ARGS "-0")
        endif()
        if (MZ_ZLIB OR MZ_LIBCOMP)
            list(APPEND COMPRESS_METHOD_NAMES "deflate")
            list(APPEND COMPRESS_METHOD_ARGS "-9")
        endif()
        if (MZ_BZIP2)
            list(APPEND COMPRESS_METHOD_NAMES "bzip2")
            list(APPEND COMPRESS_METHOD_ARGS "-b")
        endif()
        if (MZ_LZMA)
            list(APPEND COMPRESS_METHOD_NAMES "lzma")
            list(APPEND COMPRESS_METHOD_ARGS "-m")
        endif()
        list(LENGTH COMPRESS_METHOD_NAMES COMPRESS_METHOD_COUNT)
        math(EXPR COMPRESS_METHOD_COUNT "${COMPRESS_METHOD_COUNT}-1")
        foreach(INDEX RANGE ${COMPRESS_METHOD_COUNT})
            list(GET COMPRESS_METHOD_NAMES ${INDEX} COMPRESS_METHOD_NAME)
            list(GET COMPRESS_METHOD_ARGS ${INDEX} COMPRESS_METHOD_ARG)
            add_test(NAME ${COMPRESS_METHOD_NAME}-zip-${EXTRA_NAME}
                     COMMAND minizip_cmd ${COMPRESS_METHOD_ARG} -o ${EXTRA_ARGS}
                        result.zip test.c test.h empty.txt random.bin uniform.bin fuzz
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            add_test(NAME ${COMPRESS_METHOD_NAME}-list-${EXTRA_NAME}
                     COMMAND minizip_cmd -l ${EXTRA_ARGS} result.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT MZ_COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-unzip-${EXTRA_NAME}
                         COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out result.zip
                         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
            add_test(NAME ${COMPRESS_METHOD_NAME}-append-${EXTRA_NAME}
                    COMMAND minizip_cmd ${COMPRESS_METHOD_ARG} -a ${EXTRA_ARGS}
                        result.zip single.txt
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT MZ_COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-append-unzip-${EXTRA_NAME}
                            COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out result.zip
                            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
            add_test(NAME ${COMPRESS_METHOD_NAME}-erase-${EXTRA_NAME}
                    COMMAND minizip_cmd -o -e result.zip test.c test.h
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT MZ_COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-erase-unzip-${EXTRA_NAME}
                         COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out result.zip
                         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
        endforeach()
    endfunction()

    # Perform tests against ourself
    create_compress_tests("generic" "")
    create_compress_tests("span" "-k;1024")
    create_compress_tests("zipcd" "-z")
    if(MZ_PKCRYPT)
        create_compress_tests("pkcrypt" "-p;test123")
    endif()
    if(MZ_WZAES)
        create_compress_tests("wzaes" "-s;-p;test123")
    endif()
    if(MZ_SIGNING)
        create_compress_tests("signed" "-h;test.p12;-w;test")
        create_compress_tests("secure" "-z;-h;test.p12;-w;test")
    endif()

    # Perform tests on others
    if(NOT MZ_COMPRESS_ONLY)
        if(MZ_ZLIB)
            add_test(NAME unzip-tiny
                     COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out
                        fuzz/unzip_fuzzer_seed_corpus/tiny.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(MZ_BZIP2)
            add_test(NAME unzip-bzip2
                     COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out
                        fuzz/unzip_fuzzer_seed_corpus/bzip2.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(MZ_LZMA)
            add_test(NAME unzip-lzma
                     COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out
                        fuzz/unzip_fuzzer_seed_corpus/lzma.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(MZ_PKCRYPT)
            add_test(NAME unzip-pkcrypt
                     COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out -p test123
                        fuzz/unzip_fuzzer_seed_corpus/encrypted_pkcrypt.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(MZ_WZAES)
            add_test(NAME unzip-wzaes
                     COMMAND minizip_cmd -x -o ${EXTRA_ARGS} -d out -p test123
                        fuzz/unzip_fuzzer_seed_corpus/encrypted_wzaes.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
    endif()
    if(NOT MZ_COMPRESS_ONLY AND NOT MZ_DECOMPRESS_ONLY)
        if(MZ_ZLIB AND NOT MZ_LIBCOMP)
            add_test(NAME gz
                COMMAND minigzip_cmd random.bin
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            add_test(NAME ungz
                COMMAND minigzip_cmd -x -d out random.bin.gz
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
    endif()
endif()

#Build fuzzer executables
if(MZ_BUILD_FUZZ_TEST)
    if(CMAKE_C_COMPILER_ID STREQUAL "Clang")
        enable_language(CXX)

        if(DEFINED ENV{LIB_FUZZING_ENGINE})
            set(FUZZING_ENGINE $ENV{LIB_FUZZING_ENGINE})
            set(FUZZING_ENGINE_FOUND TRUE)
        else()
            find_library(FUZZING_ENGINE "FuzzingEngine")
        endif()
    endif()

    if(NOT FUZZING_ENGINE_FOUND)
        set(FUZZER_SRC "test/fuzz/standalone.c")
    else()
        set(FUZZER_SRC)
    endif()

    macro(configure_fuzz_test target)
        add_executable(${target} "test/fuzz/${target}.c" ${FUZZER_SRC})
        set_target_properties(${target} PROPERTIES LINKER_LANGUAGE CXX)
        target_compile_definitions(${target} PRIVATE ${STDLIB_DEF})
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

        target_link_libraries(${target} ${PROJECT_NAME})
        if(FUZZING_ENGINE_FOUND)
            target_link_libraries(${target} ${FUZZING_ENGINE})
        endif()
    endmacro()

    configure_fuzz_test(zip_fuzzer)
    configure_fuzz_test(unzip_fuzzer)

    if(NOT SKIP_INSTALL_BINARIES AND NOT SKIP_INSTALL_ALL)
        install(TARGETS zip_fuzzer RUNTIME DESTINATION "bin")
        install(TARGETS unzip_fuzzer RUNTIME DESTINATION "bin")
    endif()
endif()

add_feature_info(MZ_COMPAT MZ_COMPAT "Enables compatibility layer")
add_feature_info(MZ_ZLIB MZ_ZLIB "Enables ZLIB compression")
add_feature_info(MZ_BZIP2 MZ_BZIP2 "Enables BZIP2 compression")
add_feature_info(MZ_LZMA MZ_LZMA "Enables LZMA compression")
add_feature_info(MZ_PKCRYPT MZ_PKCRYPT "Enables PKWARE traditional encryption")
add_feature_info(MZ_WZAES MZ_WZAES "Enables WinZIP AES encryption")
add_feature_info(MZ_LIBCOMP MZ_LIBCOMP "Enables Apple compression")
add_feature_info(MZ_OPENSSL MZ_OPENSSL "Enables OpenSSL for encryption")
add_feature_info(MZ_BRG MZ_BRG "Enables Brian Gladman's encryption library")
add_feature_info(MZ_SIGNING MZ_SIGNING "Enables zip signing support")
add_feature_info(MZ_COMPRESS_ONLY MZ_COMPRESS_ONLY "Only support compression")
add_feature_info(MZ_DECOMPRESS_ONLY MZ_DECOMPRESS_ONLY "Only support decompression")
add_feature_info(MZ_BUILD_TEST MZ_BUILD_TEST "Builds minizip test executable")
add_feature_info(MZ_BUILD_UNIT_TEST MZ_BUILD_UNIT_TEST "Builds minizip unit test project")
add_feature_info(MZ_BUILD_FUZZ_TEST MZ_BUILD_FUZZ_TEST "Builds minizip fuzzer executables")
add_feature_info(MZ_CODE_COVERAGE MZ_CODE_COVERAGE "Builds with code coverage flags")

feature_summary(WHAT ENABLED_FEATURES DISABLED_FEATURES INCLUDE_QUIET_PACKAGES)
