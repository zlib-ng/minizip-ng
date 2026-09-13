# Find libbsd from its libbsd-overlay pkg-config module
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_LIBBSD QUIET IMPORTED_TARGET GLOBAL libbsd-overlay)
endif()

if(PC_LIBBSD_FOUND AND NOT TARGET LibBSD::LibBSD)
    add_library(LibBSD::LibBSD INTERFACE IMPORTED GLOBAL)
    set_target_properties(LibBSD::LibBSD PROPERTIES INTERFACE_LINK_LIBRARIES PkgConfig::PC_LIBBSD)
endif()

set(LibBSD_LIBRARIES ${PC_LIBBSD_LIBRARIES})
set(LibBSD_LIBRARY_DIRS ${PC_LIBBSD_LIBRARY_DIRS})
set(LibBSD_VERSION ${PC_LIBBSD_VERSION})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibBSD
    REQUIRED_VARS PC_LIBBSD_LINK_LIBRARIES
    VERSION_VAR LibBSD_VERSION)
