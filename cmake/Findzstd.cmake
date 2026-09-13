# Find zstd from its CMake package config or pkg-config
find_package(zstd CONFIG QUIET)

if(zstd_FOUND)
    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(zstd CONFIG_MODE)
    return()
endif()

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_ZSTD QUIET IMPORTED_TARGET GLOBAL libzstd)
endif()

if(PC_ZSTD_FOUND AND NOT TARGET zstd::libzstd)
    add_library(zstd::libzstd INTERFACE IMPORTED GLOBAL)
    set_target_properties(zstd::libzstd PROPERTIES INTERFACE_LINK_LIBRARIES PkgConfig::PC_ZSTD)
endif()

set(zstd_VERSION ${PC_ZSTD_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(zstd
    REQUIRED_VARS PC_ZSTD_LINK_LIBRARIES
    VERSION_VAR zstd_VERSION)
