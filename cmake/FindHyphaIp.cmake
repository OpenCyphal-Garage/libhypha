message(STATUS ">>> Found Hypha IP!")
find_path(HYPHA_IP_INCLUDE_DIR include/hypha_ip/hypha_ip.h)
find_library(HYPHA_IP_LIBRARY hypha-ip)
mark_as_advanced(HYPHA_IP_INCLUDE_DIR HYPHA_IP_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(HYPHA_IP
    REQUIRED_VARS HYPHA_IP_LIBRARY HYPHA_IP_INCLUDE_DIR
)

if (HYPHA_IP_FOUND AND NOT TARGET HyphaIp::hypha-ip)
    add_library(HyphaIp::hypha-ip UNKNOWN IMPORTED)
    set_target_properties(HyphaIp::hypha-ip PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES C
        IMPORTED_LOCATION "${HYPHA_IP_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${HYPHA_IP_INCLUDE_DIR}"
    )
endif()