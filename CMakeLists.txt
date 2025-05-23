cmake_minimum_required(VERSION 3.31.0)

project(HyphaIP LANGUAGES C VERSION 0.1.0)
enable_testing()
include(FetchContent)

set(CMAKE_C_STANDARD 23)

option(BUILD_SHARED_LIBS "Builds libraries as dynamic objects" OFF)
option(BUILD_UNIT_TESTS "Builds the unit tests" ON)

###############################################################
# Interface Libraries
###############################################################
add_library(hypha_ip_defs INTERFACE)
target_compile_definitions(hypha_ip_defs INTERFACE
    HYPHA_IP_TTL=128
    HYPHA_IP_MTU=1500
    $<$<BOOL:${BUILD_UNIT_TESTS}>:HYPHA_IP_UNIT_TEST=1>
)

add_library(hypha_ip_rules INTERFACE)
target_compile_options(hypha_ip_rules
    INTERFACE
        -Wall -Werror -Wextra -Wconversion -Wformat=2 -Wshadow
        -Wunused-parameter -Wunused-variable -Wstrict-prototypes -Wredundant-decls
        -pedantic
        -fdiagnostics-color=always
)
###############################################################
# Static or Dynamic Library
###############################################################
set(HYPHA_IP_SOURCE
    ${CMAKE_SOURCE_DIR}/source/hypha_api.c
    ${CMAKE_SOURCE_DIR}/source/hypha_arp.c
    ${CMAKE_SOURCE_DIR}/source/hypha_checksum.c
    ${CMAKE_SOURCE_DIR}/source/hypha_eth.c
    ${CMAKE_SOURCE_DIR}/source/hypha_ip.c
    ${CMAKE_SOURCE_DIR}/source/hypha_udp.c
    ${CMAKE_SOURCE_DIR}/source/hypha_icmp.c
    ${CMAKE_SOURCE_DIR}/source/hypha_igmp.c
    ${CMAKE_SOURCE_DIR}/source/hypha_span.c
    ${CMAKE_SOURCE_DIR}/source/hypha_status.c
    ${CMAKE_SOURCE_DIR}/source/hypha_print.c
    ${CMAKE_SOURCE_DIR}/source/hypha_flip.c
)
add_library(lib-hypha-ip
    ${HYPHA_IP_SOURCE}
)
target_include_directories(lib-hypha-ip PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
target_include_directories(lib-hypha-ip PRIVATE
    ${CMAKE_SOURCE_DIR}/source/include
)
target_link_libraries(lib-hypha-ip INTERFACE hypha_ip_defs hypha_ip_rules)
###############################################################
# Unit Tests
###############################################################
if (BUILD_UNIT_TESTS)
FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.5.2  # Use latest stable version
)
FetchContent_MakeAvailable(unity)
# Unit Test
add_executable(hypha_ip_test)
# target_link_libraries(hypha_ip_test PRIVATE lib-hypha-ip)
target_sources(hypha_ip_test PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/hypha_test.c
    ${CMAKE_SOURCE_DIR}/tests/unity_main.c
)
target_include_directories(hypha_ip_test PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
target_include_directories(hypha_ip_test PRIVATE
    ${CMAKE_SOURCE_DIR}/source/include
)
target_link_libraries(hypha_ip_test PRIVATE lib-hypha-ip unity)
target_link_libraries(hypha_ip_test INTERFACE  hypha_ip_defs hypha_ip_rules)
add_test(NAME hypha_ip_test COMMAND hypha_ip_test)
endif()

