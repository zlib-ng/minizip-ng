# Install script for directory: /home/runner/work/minizip-ng/minizip-ng

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

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/libminizip.a")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake"
         "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/CMakeFiles/Export/4fe77da0f4d2c94dd906efce3aa1c0aa/minizip.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip/minizip.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/CMakeFiles/Export/4fe77da0f4d2c94dd906efce3aa1c0aa/minizip.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/CMakeFiles/Export/4fe77da0f4d2c94dd906efce3aa1c0aa/minizip-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/minizip" TYPE FILE FILES
    "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/minizip-config-version.cmake"
    "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/minizip-config.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/minizip" TYPE FILE FILES
    "/home/runner/work/minizip-ng/minizip-ng/mz.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_os.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_crypt.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_buf.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_mem.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_split.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_os.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_zip.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_zip_rw.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_zlib.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_zstd.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_pkcrypt.h"
    "/home/runner/work/minizip-ng/minizip-ng/mz_strm_wzaes.h"
    "/home/runner/work/minizip-ng/minizip-ng/compat/ioapi.h"
    "/home/runner/work/minizip-ng/minizip-ng/compat/unzip.h"
    "/home/runner/work/minizip-ng/minizip-ng/compat/zip.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig" TYPE FILE FILES "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/minizip.pc")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
if(CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_COMPONENT MATCHES "^[a-zA-Z0-9_.+-]+$")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
  else()
    string(MD5 CMAKE_INST_COMP_HASH "${CMAKE_INSTALL_COMPONENT}")
    set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INST_COMP_HASH}.txt")
    unset(CMAKE_INST_COMP_HASH)
  endif()
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/home/runner/work/minizip-ng/minizip-ng/_codeql_build_dir/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
