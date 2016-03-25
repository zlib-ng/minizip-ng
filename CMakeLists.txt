#***************************************************************************
# Copyright:  Matthias Schmieder,
# E-Mail:     schmieder.matthias@gmail.com
# Year:       2016
#***************************************************************************
cmake_minimum_required(VERSION 2.8)


# Set a consistent MACOSX_RPATH default across all CMake versions. 
# When CMake 2.8.12 is required, change this default to 1.
# When CMake 3.0.0 is required, remove this block (see CMP0042).
if(NOT DEFINED CMAKE_MACOSX_RPATH)
  set(CMAKE_MACOSX_RPATH 0)
endif()

project("minizip")

# set cmake debug postfix to d
set(CMAKE_DEBUG_POSTFIX "d")


set(MINIZIP_SRC "ioapi.c"
  "ioapi_buf.c"
  "ioapi_mem.c"
  "unzip.c"
  "zip.c")

set(MINIZIP_PUBLIC_HEADERS "crypt.h"
  "ioapi.h"
  "ioapi_buf.h"
  "ioapi_mem.h"
  "unzip.h"
  "zip.h")

if(WIN32)
  list(APPEND MINIZIP_SRC "iowin32.c")
  list(APPEND MINIZIP_PUBLIC_HEADERS "iowin32.h")
endif()

option(USE_AES "enables building of aes library" ON)
if(USE_AES)
  add_definitions(-O -DHAVE_AES)
  set(AES_SRC 
    aes/aescrypt.c
    aes/aeskey.c
    aes/aestab.c
    aes/entropy.c
    aes/fileenc.c
    aes/hmac.c
    aes/prng.c
    aes/pwd2key.c
    aes/sha1.c)

  set(AES_PUBLIC_HEADERS 
    aes/aes.h
    aes/aes_via_ace.h
    aes/aesopt.h
    aes/aestab.h
    aes/brg_endian.h
    aes/brg_types.h
    aes/entropy.h
    aes/fileenc.h
    aes/hmac.h
    aes/prng.h
    aes/pwd2key.h
    aes/sha1.h)

  add_library(aes ${AES_SRC} ${AES_PUBLIC_HEADERS})

  install(TARGETS aes
    RUNTIME DESTINATION "bin"
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib")

  install(FILES ${AES_PUBLIC_HEADERS}
    DESTINATION "includes/minizip/aes")
endif()

# create minizip library
add_library(minzip ${MINIZIP_SRC} ${MINIZIP_PUBLIC_HEADERS})

if(TARGET aes)
  target_link_libraries(minzip aes)
endif()

install(TARGETS minzip 
  INCLUDES DESTINATION "include/minzip/"
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib")

install(FILES ${MINIZIP_PUBLIC_HEADERS}
  DESTINATION "includes/minizip")

option (BUILD_TEST "enabled building of executables minizip and miniunz. Requires ZLIB!" OFF)
if(BUILD_TEST)
  find_package(ZLIB REQUIRED)
  add_executable(miniunz_exec miniunz.c)
  target_link_libraries(miniunz_exec minzip ZLIB::ZLIB)

  add_executable(minizip_exec minizip.c)
  target_link_libraries(minizip_exec minzip ZLIB::ZLIB)

  install(TARGETS miniunz_exec minizip_exec
    RUNTIME DESTINATION "bin")
endif()

