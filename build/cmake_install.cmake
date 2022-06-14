# Install script for directory: /Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/objdump")
endif()

set(CMAKE_BINARY_DIR "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build")

if(NOT PLATFORM_NAME)
  if(NOT "$ENV{PLATFORM_NAME}" STREQUAL "")
    set(PLATFORM_NAME "$ENV{PLATFORM_NAME}")
  endif()
  if(NOT PLATFORM_NAME)
    set(PLATFORM_NAME iphoneos)
  endif()
endif()

if(NOT EFFECTIVE_PLATFORM_NAME)
  if(NOT "$ENV{EFFECTIVE_PLATFORM_NAME}" STREQUAL "")
    set(EFFECTIVE_PLATFORM_NAME "$ENV{EFFECTIVE_PLATFORM_NAME}")
  endif()
  if(NOT EFFECTIVE_PLATFORM_NAME)
    set(EFFECTIVE_PLATFORM_NAME -iphoneos)
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/Debug${EFFECTIVE_PLATFORM_NAME}/libminizip.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/Release${EFFECTIVE_PLATFORM_NAME}/libminizip.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/MinSizeRel${EFFECTIVE_PLATFORM_NAME}/libminizip.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
    endif()
  elseif("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/RelWithDebInfo${EFFECTIVE_PLATFORM_NAME}/libminizip.a")
    if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a" AND
       NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
      execute_process(COMMAND "ranlib" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/libminizip.a")
    endif()
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake")
    file(DIFFERENT EXPORT_FILE_CHANGED FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake"
         "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip.cmake")
    if(EXPORT_FILE_CHANGED)
      file(GLOB OLD_CONFIG_FILES "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip-*.cmake")
      if(OLD_CONFIG_FILES)
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake\" will be replaced.  Removing files [${OLD_CONFIG_FILES}].")
        file(REMOVE ${OLD_CONFIG_FILES})
      endif()
    endif()
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip.cmake")
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip-debug.cmake")
  endif()
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip-minsizerel.cmake")
  endif()
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip-relwithdebinfo.cmake")
  endif()
  if("${CMAKE_INSTALL_CONFIG_NAME}" MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/CMakeFiles/Export/lib/cmake/minizip/minizip-release.cmake")
  endif()
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/minizip-config-version.cmake"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/minizip-config.cmake"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE FILES
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_os.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_crypt.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_buf.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_mem.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_split.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_os.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_zip.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_zip_rw.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_libcomp.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_bzip.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_pkcrypt.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_strm_wzaes.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/mz_compat.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/zip.h"
    "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/unzip.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/minizip.pc")
endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/Users/alina/Desktop/rd2/Dependencies/rdarchiver/Dependencies/minizip/build/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
