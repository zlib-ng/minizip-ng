#***************************************************************************
# Copyright (C) 2017-2018 Nathan Moinvaziri
#                         https://github.com/nmoinvaz/minizip
# Copyright (C)      2016 Matthias Schmieder
#                         schmieder.matthias@gmail.com
#***************************************************************************

cmake_minimum_required(VERSION 3.0.2)
message(STATUS "Using CMake version ${CMAKE_VERSION}")

option(USE_COMPAT "Enables compatibility layer" ON)
option(USE_ZLIB "Enables ZLIB compression" ON)
option(USE_BZIP2 "Enables BZIP2 compression" ON)
option(USE_LZMA "Enables LZMA compression" ON)
option(USE_PKCRYPT "Enables PKWARE traditional encryption" ON)
option(USE_WZAES "Enables WinZIP AES encryption" ON)
option(USE_LIBCOMP "Enables Apple compression" OFF)
option(USE_OPENSSL "Enables OpenSSL for encryption" OFF)
option(USE_BRG "Enables Brian Gladman's encryption library" OFF)
option(COMPRESS_ONLY "Only support compression" OFF)
option(DECOMPRESS_ONLY "Only support decompression" OFF)
option(BUILD_TEST "Builds minizip test executable" OFF)
option(BUILD_UNIT_TEST "Builds minizip unit test project" OFF)
option(BUILD_FUZZ_TEST "Builds minizip fuzzer executables" OFF)

project("minizip" C)

# Minizip library version
set(VERSION "2.8.1")

# Minizip api version
set(SOVERSION "2.5")

include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)
include(GNUInstallDirs)
include(ExternalProject)

set(INSTALL_BIN_DIR ${CMAKE_INSTALL_FULL_BINDIR} CACHE PATH "Installation directory for executables")
set(INSTALL_LIB_DIR ${CMAKE_INSTALL_FULL_LIBDIR} CACHE PATH "Installation directory for libraries")
set(INSTALL_INC_DIR ${CMAKE_INSTALL_FULL_INCLUDEDIR} CACHE PATH "Installation directory for headers")
set(INSTALL_MAN_DIR ${CMAKE_INSTALL_FULL_MANDIR} CACHE PATH "Installation directory for manual pages")
set(INSTALL_PKGCONFIG_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" CACHE PATH "Installation directory for pkgconfig (.pc) files")
set(INSTALL_CMAKE_DIR "${CMAKE_INSTALL_FULL_LIBDIR}/cmake/minizip" CACHE PATH "Installation directory for cmake files.")

set(MINIZIP_PC ${CMAKE_CURRENT_BINARY_DIR}/minizip.pc)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/minizip.pc.cmakein ${MINIZIP_PC} @ONLY)

set(PROJECT_NAME libminizip)

# Ensure correct version of zlib is referenced
if(USE_ZLIB AND NOT USE_LIBCOMP)
    set(ZLIB_ROOT ${DEF_ZLIB_ROOT} CACHE PATH "Parent directory of zlib installation")
    find_package(ZLIB)
    if(ZLIB_FOUND)
        message(STATUS "Using ZLIB ${ZLIB_VERSION_STRING}")
        include_directories(${ZLIB_INCLUDE_DIRS})
    else()
        if (NOT ZLIB_TAG)
            set(ZLIB_TAG master)
        endif()
        if (NOT ZLIB_REPOSITORY)
            set(ZLIB_REPOSITORY https://github.com/madler/zlib)
        endif()

        message(STATUS "Using ZLIB ${ZLIB_REPOSITORY} ${ZLIB_TAG}")

        set(ZLIB_SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib/zlib)
        set(ZLIB_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/install/zlib)
        set(ZLIB_INCLUDE_DIRS ${ZLIB_INSTALL_DIR}/include)

        if(WIN32)
            if(${CMAKE_GENERATOR} MATCHES "Visual Studio.*")
                set(ZLIB_LIBRARIES
                    debug ${ZLIB_INSTALL_DIR}/lib/zlibstaticd.lib
                    optimized ${ZLIB_INSTALL_DIR}/lib/zlibstatic.lib)
            else()
                if(CMAKE_BUILD_TYPE EQUAL Debug)
                    set(ZLIB_LIBRARIES
                        ${ZLIB_INSTALL_DIR}/lib/zlibstaticd.lib)
                else()
                    set(ZLIB_LIBRARIES
                        ${ZLIB_INSTALL_DIR}/lib/zlibstatic.lib)
                endif()
            endif()
        else()
            set(ZLIB_LIBRARIES
                ${ZLIB_INSTALL_DIR}/lib/libz.a)
        endif()
        
        ExternalProject_Add(zlib
            PREFIX zlib
            GIT_REPOSITORY ${ZLIB_REPOSITORY}
            GIT_TAG ${ZLIB_TAG}
            SOURCE_DIR ${ZLIB_SOURCE_DIR}
            BUILD_IN_SOURCE 1
            INSTALL_DIR ${ZLIB_INSTALL_DIR}
            BUILD_BYPRODUCTS ${ZLIB_STATIC_LIBRARIES}
            UPDATE_COMMAND ""
            CMAKE_CACHE_ARGS
                -DCMAKE_INSTALL_PREFIX:STRING=${ZLIB_INSTALL_DIR}
                -DZLIB_COMPAT:STRING=ON
        )

        include_directories(${ZLIB_INCLUDE_DIRS})
    endif()
endif()

# Check if bzip2 installation is present
if(USE_BZIP2)
    set(BZIP2_ROOT ${DEF_BZIP2_ROOT} CACHE PATH "Parent directory of bzip2 installation")
    find_package(BZip2)
    if(BZIP2_FOUND)
        message(STATUS "Using BZIP2 ${BZIP2_VERSION_STRING}")
        include_directories(${BZIP2_INCLUDE_DIRS})
        add_definitions(-DHAVE_BZIP2)
    endif()
endif()

# Check to see if openssl installation is present
if (USE_OPENSSL)
    set(OPENSSL_ROOT ${DEF_OPENSSL_ROOT} CACHE PATH "Parent directory of openssl installation")
    find_package(OpenSSL)
    if (OPENSSL_FOUND)
        message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
        include_directories(${OPENSSL_INCLUDE_DIRS})
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

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Setup predefined macros
if(COMPRESS_ONLY)
    add_definitions(-DMZ_ZIP_NO_DECOMPRESSION)
endif()
if(DECOMPRESS_ONLY)
    add_definitions(-DMZ_ZIP_NO_COMPRESSION)
endif()
if(NOT USE_PKCRYPT AND NOT USE_WZAES)
    add_definitions(-DMZ_ZIP_NO_ENCRYPTION)
endif()

# Check for system includes
check_include_file(stdint.h   HAVE_STDINT_H)
check_include_file(inttypes.h HAVE_INTTYPES_H)

if(HAVE_STDINT_H)
    add_definitions(-DHAVE_STDINT_H)
endif()
if(HAVE_INTTYPES_H)
    add_definitions(-DHAVE_INTTYPES_H)
endif()

# Check for large file support
check_type_size(off64_t OFF64_T)
if(HAVE_OFF64_T)
    add_definitions(-D__USE_FILE_OFFSET64)
    add_definitions(-D__USE_LARGEFILE64)
    add_definitions(-D_LARGEFILE64_SOURCE)
    add_definitions(-D_FILE_OFFSET_BITS=64)
endif()
# Check for fseeko support
check_function_exists(fseeko HAVE_FSEEKO)
if(NOT HAVE_FSEEKO)
    add_definitions(-DNO_FSEEKO)
endif()

# Windows specific
if(WIN32)
    set(CMAKE_DEBUG_POSTFIX "d")
    add_definitions(-D_CRT_SECURE_NO_DEPRECATE)

    list(APPEND MINIZIP_SRC "mz_os_win32.c" "mz_strm_os_win32.c")
    if (USE_PKCRYPT OR USE_WZAES)
        if (NOT USE_OPENSSL AND NOT OPENSSL_FOUND AND NOT USE_BRG)
            list(APPEND MINIZIP_SRC "mz_crypt_win32.c")
        endif()
    endif()
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
    add_definitions(-DMZ_WINRT_API)
endif()

# Unix specific
if(UNIX)
    add_definitions(-D_POSIX_C_SOURCE=200112L)
    list(APPEND MINIZIP_SRC "mz_os_posix.c" "mz_strm_os_posix.c")
    
    if ((USE_PKCRYPT OR USE_WZAES) AND NOT (USE_OPENSSL AND OPENSSL_FOUND))
        
        if (APPLE AND NOT USE_BRG)
            list(APPEND MINIZIP_SRC "mz_crypt_apple.c")
        else()
            set(USE_BRG TRUE)
        endif()

        # Check to see which random generation functions we have 
        check_symbol_exists("getrandom" "sys/random.h" HAVE_GETRANDOM)
        if (HAVE_GETRANDOM)
            add_definitions(-DHAVE_GETRANDOM)
        endif()
        check_symbol_exists("arc4random_buf" "stdlib.h" HAVE_ARC4RANDOM_BUF)
        if (HAVE_ARC4RANDOM_BUF)
            add_definitions(-DHAVE_ARC4RANDOM_BUF)
        else()
            check_symbol_exists("arc4random" "stdlib.h" HAVE_ARC4RANDOM)
            if (HAVE_ARC4RANDOM)
                add_definitions(-DHAVE_ARC4RANDOM)
            endif()
        endif()

        if(NOT HAVE_ARC4RANDOM_BUF)
            find_package(PkgConfig REQUIRED)

            pkg_check_modules(LIBBSD libbsd)
            if (LIBBSD_FOUND)
                check_library_exists("${LIBBSD_LIBRARIES}" "arc4random_buf" 
                    "${LIBBSD_LIBRARY_DIRS}" HAVE_LIBBSD_ARC4RANDOM_BUF)
                if (HAVE_LIBBSD_ARC4RANDOM_BUF)
                    add_definitions(-DHAVE_LIBBSD)
                    add_definitions(-DHAVE_ARC4RANDOM_BUF)
                    include_directories(${LIBBSD_INCLUDE_DIRS})
                    link_directories(${LIBBSD_LIBRARY_DIRS})
                endif()
            endif()
        endif()
    endif()

    find_package(Iconv)
    if (Iconv_FOUND)
        message(STATUS "Using Iconv")
        include_directories(${Iconv_INCLUDE_DIRS})
    endif()

endif()

# Include compatibility layer
if(USE_COMPAT)
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
endif()

# Include PKCRYPT
if(USE_PKCRYPT)
    add_definitions(-DHAVE_PKCRYPT)

    list(APPEND MINIZIP_SRC "mz_strm_pkcrypt.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_pkcrypt.h")
endif()

# Include WinZIP AES
if(USE_WZAES)
    add_definitions(-DHAVE_WZAES)

    list(APPEND MINIZIP_SRC "mz_strm_wzaes.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_wzaes.h")
endif()

# Include BRG
if(USE_BRG)
    list(APPEND MINIZIP_SRC "mz_crypt_brg.c")

    add_definitions(-DMZ_ZIP_NO_SIGNING)

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

    include_directories(lib/brg)

    source_group("BRG" FILES ${BRG_SRC} ${BRG_PUBLIC_HEADERS})
endif()

# Include OpenSSL
if(USE_OPENSSL AND OPENSSL_FOUND)
    list(APPEND MINIZIP_SRC "mz_crypt_openssl.c")
endif()

# Include ZLIB
if(USE_ZLIB)
    if(USE_LIBCOMP)
        add_definitions(-DHAVE_LIBCOMP)

        list(APPEND MINIZIP_SRC "mz_strm_libcomp.c")
        list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_libcomp.h")
    else()
        add_definitions(-DHAVE_ZLIB)

        list(APPEND MINIZIP_SRC "mz_strm_zlib.c")
        list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_zlib.h")
        
        if (ZLIB_FOUND)
            include(CheckFunctionExists)
            check_function_exists(z_get_crc_table NEEDS_Z_PREFIX)
            if(NEEDS_Z_PREFIX)
                add_definitions(-DZ_PREFIX)
            endif()
        endif()
    endif()
endif()

# Include BZIP2 
if(USE_BZIP2)
    add_definitions(-DHAVE_BZIP2)

    list(APPEND MINIZIP_SRC "mz_strm_bzip.c")
    list(APPEND MINIZIP_PUBLIC_HEADERS "mz_strm_bzip.h")

    if(NOT BZIP2_FOUND)
        add_definitions(-DBZ_NO_STDIO)

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

        include_directories(lib/bzip2)

        source_group("BZip2" FILES ${BZIP2_SRC} ${BZIP2_PUBLIC_HEADERS})
    endif()
endif()

# Include LZMA 
if(USE_LZMA)
    add_definitions(-DHAVE_LZMA)
    add_definitions(-DLZMA_API_STATIC)
    add_definitions(-DHAVE_CONFIG_H)

    check_include_file(limits.h     HAVE_LIMITS_H)
    check_include_file(string.h     HAVE_STRING_H)
    check_include_file(strings.h    HAVE_STRINGS_H)
    check_include_file(memory.h     HAVE_MEMORY_H)
    check_include_file(stdbool.h    HAVE_STDBOOL_H)
    check_include_file(immintrin.h  HAVE_IMMINTRIN_H)

    if(HAVE_LIMITS_H)
        add_definitions(-DHAVE_LIMITS_H)
    endif()
    if(HAVE_STRING_H)
        add_definitions(-DHAVE_STRING_H)
    endif()
    if(HAVE_STRINGS_H)
        add_definitions(-DHAVE_STRINGS_H)
    endif()
    if(HAVE_MEMORY_H)
        add_definitions(-DHAVE_MEMORY_H)
    endif()
    if(HAVE_STDBOOL_H)
        add_definitions(-DHAVE_STDBOOL_H)
    endif()
    if(HAVE_IMMINTRIN_H)
        add_definitions(-DHAVE_IMMINTRIN_H)
    endif()

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

    include_directories(lib/liblzma
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

# Enable x86 optimizations if supported
if(CMAKE_BUILD_TYPE MATCHES Release)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        include(CheckCCompilerFlag)

        macro(enable_option_if_supported option variable)
            check_c_compiler_flag("-Werror=unused-command-line-argument ${option}" ${variable})
            if(${variable})
                add_compile_options(${option})
            endif()
        endmacro()

        enable_option_if_supported(-msse3 check_opt_sse3)
        enable_option_if_supported(-msse4.1 check_opt_sse41)
        enable_option_if_supported(-maes check_opt_aes)
    endif()

    if(NOT MSVC)
        add_compile_options(-O3)
    endif()
else()
    if(MSVC)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Zi")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    endif()
endif()

# Enable compiler warnings
if(MSVC)
    add_compile_options(/W3)
else()
    add_compile_options(-W -Wall)
endif()

# Create minizip library
source_group("Minizip" FILES ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS})

add_library(${PROJECT_NAME}
                ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS}
                ${BRG_SRC} ${BRG_PUBLIC_HEADERS}
                ${BZIP2_SRC} ${BZIP2_PUBLIC_HEADERS}
                ${LZMA_SRC} ${LZMA_PUBLIC_HEADERS})

set_target_properties(${PROJECT_NAME} PROPERTIES 
                        VERSION ${VERSION} 
                        SOVERSION ${SOVERSION}
                        LINKER_LANGUAGE C
                        PREFIX ""
                        POSITION_INDEPENDENT_CODE 1)
if(USE_LZMA)
    set_target_properties(${PROJECT_NAME} PROPERTIES C_STANDARD 99)
endif()
if (MSVC AND BUILD_SHARED_LIBS)
    set_target_properties(${PROJECT_NAME} PROPERTIES ARCHIVE_OUTPUT_NAME "minizip")
endif ()

# Link with external libraries
if(USE_ZLIB AND NOT USE_LIBCOMP)
    target_link_libraries(${PROJECT_NAME} ${ZLIB_LIBRARIES})
    if(NOT ZLIB_FOUND)
        add_dependencies(${PROJECT_NAME} zlib)
    endif()
endif()
if(USE_BZIP2 AND BZIP2_FOUND)
    target_link_libraries(${PROJECT_NAME} ${BZIP2_LIBRARIES})
endif()
if(USE_LIBCOMP)
    target_link_libraries(${PROJECT_NAME} compression)
endif()
if(Iconv_FOUND AND NOT Iconv_IS_BUILT_IN)
    target_link_libraries(${PROJECT_NAME} ${Iconv_LIBRARIES})
endif()
if(USE_OPENSSL AND OPENSSL_FOUND)
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
elseif(UNIX)
    if(APPLE AND NOT USE_BRG)
        message(STATUS "Using Security Framework")
        target_link_libraries(${PROJECT_NAME} "-framework CoreFoundation")
        target_link_libraries(${PROJECT_NAME} "-framework Security")
        set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,-F/Library/Frameworks")
    else()
        target_link_libraries(${PROJECT_NAME} ${LIBBSD_LIBRARIES})
    endif()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC $<INSTALL_INTERFACE:${INSTALL_INC_DIR}>)

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
endif()
if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL)
    install(FILES ${MINIZIP_PUBLIC_HEADERS} DESTINATION "${INSTALL_INC_DIR}")
endif()
if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL)
    install(FILES ${MINIZIP_PC} DESTINATION "${INSTALL_PKGCONFIG_DIR}")
endif()

# Build test executable
if(BUILD_TEST)
    add_executable(minizip "minizip.c" "test/test.c" "test/test.h")
    target_link_libraries(minizip ${PROJECT_NAME})

    if(NOT SKIP_INSTALL_BINARIES AND NOT SKIP_INSTALL_ALL)
        install(TARGETS minizip RUNTIME DESTINATION "bin")
    endif()
endif()

if(BUILD_UNIT_TEST)
    enable_testing()

    function(create_compress_tests EXTRA_NAME EXTRA_ARGS)
        if(DECOMPRESS_ONLY)
            return()
        endif()
        list(FIND EXTRA_ARGS "-z" ZIPCD_IDX)
        if(${ZIPCD_IDX} EQUAL -1)
            set(COMPRESS_METHOD_NAMES "raw")
            set(COMPRESS_METHOD_ARGS "-0")
        endif()
        if (USE_ZLIB OR USE_LIBCOMP)
            list(APPEND COMPRESS_METHOD_NAMES "deflate")
            list(APPEND COMPRESS_METHOD_ARGS "-9")
        endif()
        if (USE_BZIP2)
            list(APPEND COMPRESS_METHOD_NAMES "bzip2")
            list(APPEND COMPRESS_METHOD_ARGS "-b")
        endif()
        if (USE_LZMA)
            list(APPEND COMPRESS_METHOD_NAMES "lzma")
            list(APPEND COMPRESS_METHOD_ARGS "-m")
        endif()
        list(LENGTH COMPRESS_METHOD_NAMES COMPRESS_METHOD_COUNT)
        math(EXPR COMPRESS_METHOD_COUNT "${COMPRESS_METHOD_COUNT}-1")
        foreach(INDEX RANGE ${COMPRESS_METHOD_COUNT})
            list(GET COMPRESS_METHOD_NAMES ${INDEX} COMPRESS_METHOD_NAME)
            list(GET COMPRESS_METHOD_ARGS ${INDEX} COMPRESS_METHOD_ARG)
            add_test(NAME ${COMPRESS_METHOD_NAME}-zip-${EXTRA_NAME}
                     COMMAND minizip ${COMPRESS_METHOD_ARG} -o ${EXTRA_ARGS} 
                        result.zip test.c test.h empty.txt random.bin uniform.bin fuzz
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            add_test(NAME ${COMPRESS_METHOD_NAME}-list-${EXTRA_NAME}
                     COMMAND minizip -l ${EXTRA_ARGS} result.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-unzip-${EXTRA_NAME}
                         COMMAND minizip -x -o ${EXTRA_ARGS} -d out result.zip
                         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
            add_test(NAME ${COMPRESS_METHOD_NAME}-append-${EXTRA_NAME}
                    COMMAND minizip ${COMPRESS_METHOD_ARG} -a ${EXTRA_ARGS} 
                        result.zip single.txt
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-append-unzip-${EXTRA_NAME}
                            COMMAND minizip -x -o ${EXTRA_ARGS} -d out result.zip
                            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
            add_test(NAME ${COMPRESS_METHOD_NAME}-erase-${EXTRA_NAME}
                    COMMAND minizip -o -e result.zip test.c test.h 
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            if(NOT COMPRESS_ONLY)
                add_test(NAME ${COMPRESS_METHOD_NAME}-erase-unzip-${EXTRA_NAME}
                         COMMAND minizip -x -o ${EXTRA_ARGS} -d out result.zip
                         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
            endif()
        endforeach()
    endfunction()

    # Perform tests against ourself
    create_compress_tests("generic" "")
    create_compress_tests("span" "-k;1024")
    create_compress_tests("zipcd" "-z")
    if(USE_PKCRYPT)
        create_compress_tests("pkcrypt" "-p;test123")
    endif()
    if(USE_WZAES)
        create_compress_tests("wzaes" "-s;-p;test123")
    endif()
    if(USE_OPENSSL AND OPENSSL_FOUND)
        create_compress_tests("signed" "-h;ia.p12;-w;test")
        create_compress_tests("secure" "-z;-h;ia.p12;-w;test")
    endif()
    # Perform tests on others
    if(NOT COMPRESS_ONLY)
        if(USE_ZLIB)
            add_test(NAME unzip-tiny
                     COMMAND minizip -x -o ${EXTRA_ARGS} -d out 
                        fuzz/unzip_fuzzer_seed_corpus/tiny.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(USE_BZIP2)
            add_test(NAME unzip-bzip2
                     COMMAND minizip -x -o ${EXTRA_ARGS} -d out
                        fuzz/unzip_fuzzer_seed_corpus/bzip2.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(USE_LZMA)
            add_test(NAME unzip-lzma
                     COMMAND minizip -x -o ${EXTRA_ARGS} -d out
                        fuzz/unzip_fuzzer_seed_corpus/lzma.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(USE_PKCRYPT)
            add_test(NAME unzip-pkcrypt
                     COMMAND minizip -x -o ${EXTRA_ARGS} -d out -p test123
                        fuzz/unzip_fuzzer_seed_corpus/encrypted_pkcrypt.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
        if(USE_WZAES)
            add_test(NAME unzip-wzaes
                     COMMAND minizip -x -o ${EXTRA_ARGS} -d out -p test123
                        fuzz/unzip_fuzzer_seed_corpus/encrypted_wzaes.zip
                     WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test)
        endif()
    endif()

endif()

#Build fuzzer executables
if(BUILD_FUZZ_TEST)
    if (NOT CMAKE_C_COMPILER_ID STREQUAL "Clang")
        set(FUZZER_SRC "test/fuzz/standalone.c")
    endif()

    add_executable(zip_fuzzer "test/fuzz/zip_fuzzer.c" ${FUZZER_SRC})
    add_executable(unzip_fuzzer "test/fuzz/unzip_fuzzer.c" ${FUZZER_SRC})

    if (CMAKE_C_COMPILER_ID STREQUAL "Clang")
        enable_language(CXX)
        target_link_libraries(zip_fuzzer "FuzzingEngine")
        set_target_properties(zip_fuzzer PROPERTIES LINKER_LANGUAGE CXX)
        target_link_libraries(unzip_fuzzer "FuzzingEngine")
        set_target_properties(unzip_fuzzer PROPERTIES LINKER_LANGUAGE CXX)
    endif()

    target_link_libraries(zip_fuzzer ${PROJECT_NAME})
    target_link_libraries(unzip_fuzzer ${PROJECT_NAME})

    if(NOT SKIP_INSTALL_BINARIES AND NOT SKIP_INSTALL_ALL)
        install(TARGETS zip_fuzzer RUNTIME DESTINATION "bin")
        install(TARGETS unzip_fuzzer RUNTIME DESTINATION "bin")
    endif()
endif()
