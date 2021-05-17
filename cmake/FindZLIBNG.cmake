find_path(ZLIBNG_INCLUDE_DIRS NAMES zlib-ng.h)

if(ZLIB_INCLUDE_DIRS)
    set(ZLIBNG_LIBRARY_DIRS ${ZLIBNG_INCLUDE_DIRS})

    if("${ZLIBNG_LIBRARY_DIRS}" MATCHES "/include$")
        # Strip off the trailing "/include" in the path.
        get_filename_component(ZLIBNG_LIBRARY_DIRS ${ZLIBNG_LIBRARY_DIRS} PATH)
    endif()

    if(EXISTS "${ZLIBNG_LIBRARY_DIRS}/lib")
        set(ZLIBNG_LIBRARY_DIRS ${ZLIBNG_LIBRARY_DIRS}/lib)
    endif()
endif()

find_library(ZLIBNG_LIBRARY NAMES z-ng libz-ng libz-ng.a)

set(ZLIBNG_LIBRARIES ${ZLIBNG_LIBRARY})
set(ZLIBNG_INCLUDE_DIRS ${ZLIBNG_INCLUDE_DIRS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZLIBNG DEFAULT_MSG ZLIBNG_LIBRARY ZLIBNG_INCLUDE_DIRS)

if(ZLIBNG_INCLUDE_DIRS AND ZLIBNG_LIBRARIES)
    set(ZLIBNG_FOUND ON)
else(ZLIBNG_INCLUDE_DIRS AND ZLIBNG_LIBRARIES)
    set(ZLIBNG_FOUND OFF)
endif()

if(ZLIBNG_FOUND)
    message(STATUS "Found zlib-ng: ${ZLIBNG_LIBRARIES}, ${ZLIBNG_INCLUDE_DIRS}")
endif()
