find_path(ZLIB-NG_INCLUDE_DIRS NAMES zlib-ng.h)

if(ZLIB_INCLUDE_DIRS)
    set(ZLIB-NG_LIBRARY_DIRS ${ZLIB-NG_INCLUDE_DIRS})

    if("${ZLIB-NG_LIBRARY_DIRS}" MATCHES "/include$")
        # Strip off the trailing "/include" in the path.
        get_filename_component(ZLIB-NG_LIBRARY_DIRS ${ZLIB-NG_LIBRARY_DIRS} PATH)
    endif()

    if(EXISTS "${ZLIB-NG_LIBRARY_DIRS}/lib")
        set(ZLIB-NG_LIBRARY_DIRS ${ZLIB-NG_LIBRARY_DIRS}/lib)
    endif()
endif()

find_library(ZLIB-NG_LIBRARY NAMES z-ng libz-ng libz-ng.a)

set(ZLIB-NG_LIBRARIES ${ZLIB-NG_LIBRARY})
set(ZLIB-NG_INCLUDE_DIRS ${ZLIB-NG_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZLIB-NG DEFAULT_MSG ZLIB-NG_LIBRARY ZLIB-NG_INCLUDE_DIRS)

if(ZLIB-NG_INCLUDE_DIRS AND ZLIB-NG_LIBRARIES)
    set(ZLIB-NG_FOUND ON)
else(ZLIB-NG_INCLUDE_DIRS AND ZLIB-NG_LIBRARIES)
    set(ZLIB-NG_FOUND OFF)
endif()

if(ZLIB-NG_FOUND)
    message(STATUS "Found zlib-ng: ${ZLIB-NG_LIBRARIES}, ${ZLIB-NG_INCLUDE_DIRS}")
endif()
