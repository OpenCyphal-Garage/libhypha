cmake_minimum_required(VERSION 3.31.0)

project(HyphaIp LANGUAGES C VERSION 0.2.0)
enable_testing()
include(FetchContent)

set(CMAKE_C_STANDARD 23)

option(BUILD_SHARED_LIBS "Builds libraries as dynamic objects" OFF)
option(BUILD_UNIT_TESTS "Builds the unit tests" ON)
option(BUILD_COVERAGE "Builds with coverage support" ON)
option(BUILD_ANALYSIS "Builds with static analysis support" ON)

###############################################################
# Interface Libraries
###############################################################
add_library(hypha-ip-defs INTERFACE)
target_compile_definitions(hypha-ip-defs INTERFACE
    HYPHA_IP_TTL=128
    HYPHA_IP_MTU=1500
    $<$<BOOL:${BUILD_UNIT_TESTS}>:HYPHA_IP_UNIT_TEST=1>
)

add_library(hypha-ip-rules INTERFACE)
target_compile_options(hypha-ip-rules
    INTERFACE
        -Wall -Werror -Wextra -Wconversion -Wformat=2 -Wshadow
        -Wunused-parameter -Wunused-variable -Wstrict-prototypes -Wredundant-decls
        -pedantic
        -fdiagnostics-color=always
        # GNU specific options
        $<$<AND:$<BOOL:${BUILD_ANALYSIS}>,$<C_COMPILER_ID:GNU>>:-fanalyzer>
        $<$<AND:$<BOOL:${BUILD_COVERAGE}>,$<C_COMPILER_ID:GNU>>:-ftest-coverage -fcoverage-mapping>
        # Clang specific options
        $<$<AND:$<BOOL:${BUILD_ANALYSIS}>,$<C_COMPILER_ID:Clang>>:-Xclang -analyzer-output=text>
        $<$<AND:$<BOOL:${BUILD_COVERAGE}>,$<C_COMPILER_ID:Clang>>:-fprofile-instr-generate -fprofile-arcs -ftest-coverage -fcoverage-mapping>
        # AppleClang specific options
        $<$<AND:$<BOOL:${BUILD_ANALYSIS}>,$<C_COMPILER_ID:AppleClang>>:-Xclang -analyzer-output=text>
        $<$<AND:$<BOOL:${BUILD_COVERAGE}>,$<C_COMPILER_ID:AppleClang>>:-fprofile-instr-generate -fprofile-arcs -ftest-coverage -fcoverage-mapping>
)
target_link_libraries(hypha-ip-rules INTERFACE
    $<$<BOOL:${BUILD_COVERAGE}>:--coverage>
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
add_library(hypha-ip
    ${HYPHA_IP_SOURCE}
)
target_include_directories(hypha-ip PUBLIC
    # Generated Tree
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    # Build Tree
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    # Install Tree
    $<INSTALL_INTERFACE:include>
)
target_include_directories(hypha-ip PRIVATE
    ${CMAKE_SOURCE_DIR}/source/include
)
# DO force our COMPILE DEFS on customers when they link against us so we are the same
target_link_libraries(hypha-ip PUBLIC hypha-ip-defs)
# Don't force our build flags on customers when they link against us
target_link_libraries(hypha-ip PRIVATE hypha-ip-rules)
set_target_properties(hypha-ip PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${CMAKE_SOURCE_DIR}/include/hypha_ip.h"
)

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
add_executable(hypha-ip-test)
# target_link_libraries(hypha-ip-test PRIVATE hypha-ip)
target_sources(hypha-ip-test PRIVATE
    ${CMAKE_SOURCE_DIR}/tests/hypha_test.c
    ${CMAKE_SOURCE_DIR}/tests/unity_main.c
)
target_include_directories(hypha-ip-test PUBLIC
    ${CMAKE_SOURCE_DIR}/include
)
target_include_directories(hypha-ip-test PRIVATE
    ${CMAKE_SOURCE_DIR}/source/include
)
target_link_libraries(hypha-ip-test PRIVATE hypha-ip unity)
target_link_libraries(hypha-ip-test PRIVATE hypha-ip-defs hypha-ip-rules)

add_test(NAME HyphaIpUnityTest
         COMMAND hypha-ip-test
         WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
if (BUILD_COVERAGE)
set_tests_properties(HyphaIpUnityTest PROPERTIES
    ENVIRONMENT LLVM_PROFILE_FILE=$<TARGET_FILE:hypha-ip-test>.profraw
)
endif()

###############################################################
# Example Application
###############################################################
add_executable(hypha-ip-example
    ${CMAKE_SOURCE_DIR}/examples/hypha_ip_lifecycle.c
)
target_link_libraries(hypha-ip-example PRIVATE hypha-ip)
target_link_libraries(hypha-ip-example PRIVATE hypha-ip-defs hypha-ip-rules)
endif(BUILD_UNIT_TESTS)

###############################################################
# Coverage Support
###############################################################
if (BUILD_COVERAGE)
    find_program(LLVM_PROFDATA llvm-profdata)
    find_program(LLVM_COV llvm-cov)
    find_program(GENHTML genhtml)

    if(NOT LLVM_PROFDATA OR NOT LLVM_COV OR NOT GENHTML)
        message(FATAL_ERROR "Coverage tools not found. Please install llvm-profdata, llvm-cov, and genhtml.")
    endif()

    function(coverage_target)
        # Argument parsing
        set(options "")
        set(singles TARGET)
        set(multiples LIBRARIES EXCLUDES)
        cmake_parse_arguments(
            ARG
            "${options}"
            "${singles}"
            "${multiples}"
            ${ARGN})

        if(NOT ARG_TARGET)
            message(FATAL_ERROR "No target specified for coverage")
        endif()

        message(STATUS "Coverage target: ${ARG_TARGET} with libraries: ${ARG_LIBRARIES} and excludes: ${ARG_EXCLUDES}")
        get_target_property(EXEC_OUTPUT_DIRECTORY ${ARG_TARGET} RUNTIME_OUTPUT_DIRECTORY)
        if (NOT EXEC_OUTPUT_DIRECTORY)
            set(EXEC_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakefiles/${ARG_TARGET}.dir/)
        endif()
        message(STATUS "Executable output directory for ${ARG_TARGET}: ${EXEC_OUTPUT_DIRECTORY}")
        foreach(lib ${ARG_LIBRARIES})
            get_target_property(LIBRARY_OUTPUT_DIRECTORY ${lib} LIBRARY_OUTPUT_DIRECTORY)
            if (NOT LIBRARY_OUTPUT_DIRECTORY)
                set(LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/CMakefiles/${lib}.dir/)
            endif()
            message(STATUS "Library output directory for ${lib}: ${LIBRARY_OUTPUT_DIRECTORY}")
            list(APPEND LIBRARIES_COVERAGE_PATH ${LIBRARY_OUTPUT_DIRECTORY})
            get_target_property(_SOURCES ${lib} SOURCES)
            list(APPEND LIBRARIES_SOURCES ${_SOURCES})
        endforeach()
        message(STATUS "Libraries coverage path: ${LIBRARIES_COVERAGE_PATH}")
        message(STATUS "Libraries sources: ${LIBRARIES_SOURCES}")

        # set(LLVM_PROFILE_FILE "${TARGET}.profraw")
        add_custom_target(coverage-${ARG_TARGET}
            DEPENDS ${ARG_TARGET}
            COMMAND ${LLVM_PROFDATA} merge -sparse $<TARGET_FILE:${ARG_TARGET}>.profraw -o $<TARGET_FILE:${ARG_TARGET}>.profdata
            COMMAND ${LLVM_COV} show   $<TARGET_FILE:${ARG_TARGET}> --color --sources ${LIBRARIES_SOURCES} -instr-profile=$<TARGET_FILE:${ARG_TARGET}>.profdata --format=html -output-dir=${CMAKE_BINARY_DIR}/coverage/coverage-${ARG_TARGET}
            COMMAND ${LLVM_COV} report $<TARGET_FILE:${ARG_TARGET}> --color --sources ${LIBRARIES_SOURCES} -instr-profile=$<TARGET_FILE:${ARG_TARGET}>.profdata
            COMMAND ${LLVM_COV} export $<TARGET_FILE:${ARG_TARGET}> --color --sources ${LIBRARIES_SOURCES} -instr-profile=$<TARGET_FILE:${ARG_TARGET}>.profdata -format=lcov > $<TARGET_FILE:${ARG_TARGET}>.info
            COMMAND ${GENHTML} $<TARGET_FILE:${ARG_TARGET}>.info -o ${CMAKE_BINARY_DIR}/coverage/coverage-${ARG_TARGET}
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        if (NOT TARGET coverage)
            add_custom_target(coverage)
        endif()
        add_dependencies(coverage coverage-${ARG_TARGET})
    endfunction()

    coverage_target(TARGET hypha-ip-test
                    LIBRARIES hypha-ip
                    EXCLUDES hypha-ip-test)

endif()

#####################
# EXPORTS
#####################

# Declare installs and exports
install(TARGETS hypha-ip hypha-ip-rules hypha-ip-defs EXPORT HyphaIpTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)
install(EXPORT HyphaIpTargets
    FILE HyphaIpTargets.cmake
    NAMESPACE HyphaIp::
    DESTINATION share/cmake/${PROJECT_NAME}
)
install(DIRECTORY include/hypha_ip
    DESTINATION include
    PATTERN "*.h"
    PERMISSIONS WORLD_READ GROUP_READ OWNER_READ
)
install(FILES "cmake/Find${PROJECT_NAME}.cmake" "cmake/${PROJECT_NAME}-config.cmake"
    DESTINATION share/cmake/${PROJECT_NAME}
)