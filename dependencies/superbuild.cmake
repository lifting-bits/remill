include_guard()

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)

# Bail out early for multi-config generators
if(CMAKE_CONFIGURATION_TYPES)
    message(FATAL_ERROR "Multi-config generators are not supported. Use Make/NMake/Ninja instead")
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
	message(FATAL_ERROR "In-tree builds are not supported. Run CMake from a separate directory: cmake -B build")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "")
    message(FATAL_ERROR "CMAKE_BUILD_TYPE is not set")
endif()
message(STATUS "Configuration: ${CMAKE_BUILD_TYPE}")

# Default to build/install (setting this variable is not recommended and might cause conflicts)
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_CURRENT_BINARY_DIR}/../install" CACHE PATH "Install prefix" FORCE)
endif()
cmake_path(ABSOLUTE_PATH CMAKE_INSTALL_PREFIX NORMALIZE)
set(CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}" CACHE PATH "Install prefix" FORCE)
message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

# Verify build configuration hasn't changed
set(BUILD_CONFIG_FILE "${CMAKE_INSTALL_PREFIX}/.build_config")
string(JOIN "\n" CURRENT_BUILD_CONFIG
    "CMAKE_SYSTEM=${CMAKE_SYSTEM}"
    "CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}"
    "CMAKE_CXX_COMPILER_ID=${CMAKE_CXX_COMPILER_ID}"
    "CMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
    "CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}"
)

if(EXISTS "${BUILD_CONFIG_FILE}")
    file(READ "${BUILD_CONFIG_FILE}" PREVIOUS_BUILD_CONFIG)
    if(NOT PREVIOUS_BUILD_CONFIG STREQUAL CURRENT_BUILD_CONFIG)
        message(FATAL_ERROR
            "Build configuration changed!\n"
            "[previous]\n${PREVIOUS_BUILD_CONFIG}\n"
            "[current]\n${CURRENT_BUILD_CONFIG}\n"
            "\n"
            "Please delete the build and install directories, then reconfigure:\n"
            "  cmake -E rm -rf \"${CMAKE_BINARY_DIR}\"\n"
            "  cmake -E rm -rf \"${CMAKE_INSTALL_PREFIX}\"\n"
        )
    endif()
else()
    file(MAKE_DIRECTORY "${CMAKE_INSTALL_PREFIX}")
    file(WRITE "${BUILD_CONFIG_FILE}" "${CURRENT_BUILD_CONFIG}")
endif()

# Git is necessary for submodules
find_package(Git REQUIRED)
message(STATUS "Git: ${GIT_EXECUTABLE}")

# Ninja is necessary for building the dependencies
find_program(ninja_EXECUTABLE ninja NO_CACHE NO_PACKAGE_ROOT_PATH NO_CMAKE_PATH NO_CMAKE_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH NO_CMAKE_INSTALL_PREFIX NO_CMAKE_FIND_ROOT_PATH)
if(ninja_EXECUTABLE STREQUAL "ninja_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Could not find 'ninja' in the PATH")
endif()
message(STATUS "Ninja: ${ninja_EXECUTABLE}")

# Documentation: https://cmake.org/cmake/help/latest/module/ExternalProject.html
include(ExternalProject)

# Hook for ExternalProject_Add to make sure projects build in order
function(ExternalProject_Add name)
    # The DEPENDS argument is fully implicit
    cmake_parse_arguments(HOOK "" "" DEPENDS ${ARGN})
    if(HOOK_DEPENDS)
        message(FATAL_ERROR "Explicit DEPENDS (${HOOK_DEPENDS}) not supported")
    endif()

    # Update the LAST_EXTERNAL_PROJECT property
    get_property(LAST_EXTERNAL_PROJECT GLOBAL PROPERTY LAST_EXTERNAL_PROJECT)
    set_property(GLOBAL PROPERTY LAST_EXTERNAL_PROJECT ${name})

    # Pass the previous project as a dependency to this call
    if(LAST_EXTERNAL_PROJECT)
        set(HOOK_ARGS DEPENDS "${LAST_EXTERNAL_PROJECT}")
        message(STATUS "ExternalProject: ${name} depends on ${LAST_EXTERNAL_PROJECT}")
    else()
        message(STATUS "ExternalProject: ${name}")
    endif()
    _ExternalProject_Add(${name} ${ARGN} ${HOOK_ARGS}
        # Reference: https://www.scivision.dev/cmake-external-project-ninja-verbose/
        USES_TERMINAL_DOWNLOAD ON
        USES_TERMINAL_UPDATE ON
        USES_TERMINAL_PATCH ON
        USES_TERMINAL_CONFIGURE ON
        USES_TERMINAL_BUILD ON
        USES_TERMINAL_INSTALL ON
        USES_TERMINAL_TEST ON
        DOWNLOAD_EXTRACT_TIMESTAMP ON
    )
endfunction()

if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    if(CMAKE_CXX_SIMULATE_ID STREQUAL "MSVC")
        # Suppress warnings for clang-cl builds, some of these cause compilation errors.
        list(APPEND ADDITIONAL_FLAGS "-w")
    elseif(UNIX AND NOT APPLE)
        # To compile shared libraries, everything needs to be compiled as position independent code when using clang on linux
        list(APPEND ADDITIONAL_FLAGS "-fPIC")
    endif()
endif()

# Convert a CMake list to a space-separated list
list(JOIN ADDITIONAL_FLAGS " " ADDITIONAL_FLAGS)

# Default cache variables for all projects
list(APPEND CMAKE_ARGS
    "-DCMAKE_PREFIX_PATH:FILEPATH=${CMAKE_INSTALL_PREFIX};${CMAKE_PREFIX_PATH}"
    "-DCMAKE_INSTALL_PREFIX:FILEPATH=${CMAKE_INSTALL_PREFIX}"
    "-DCMAKE_BUILD_TYPE:STRING=${CMAKE_BUILD_TYPE}"
    "-DBUILD_SHARED_LIBS:STRING=${BUILD_SHARED_LIBS}"
    "-DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}"
    "-DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}"
    "-DCMAKE_C_FLAGS:STRING=${CMAKE_C_FLAGS} ${ADDITIONAL_FLAGS}"
    "-DCMAKE_CXX_FLAGS:STRING=${CMAKE_CXX_FLAGS} ${ADDITIONAL_FLAGS}"
    "-DCMAKE_POSITION_INDEPENDENT_CODE:STRING=ON"
    "-DCMAKE_ERROR_DEPRECATED:STRING=OFF"
    "-DCMAKE_ERROR_DEVELOPER_WARNINGS:STRING=OFF"
)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0")
    list(APPEND CMAKE_ARGS
        "-DCMAKE_POLICY_VERSION_MINIMUM:STRING=${CMAKE_MINIMUM_REQUIRED_VERSION}"
    )
endif()

if(CMAKE_C_COMPILER_LAUNCHER)
    list(APPEND CMAKE_ARGS "-DCMAKE_C_COMPILER_LAUNCHER:STRING=${CMAKE_C_COMPILER_LAUNCHER}")
endif()
if(CMAKE_CXX_COMPILER_LAUNCHER)
    list(APPEND CMAKE_ARGS "-DCMAKE_CXX_COMPILER_LAUNCHER:STRING=${CMAKE_CXX_COMPILER_LAUNCHER}")
endif()

message(STATUS "Compiling all dependencies with the following CMake arguments:")
foreach(CMAKE_ARG ${CMAKE_ARGS})
    message("\t${CMAKE_ARG}")
endforeach()

function(simple_git repo tag)
    get_filename_component(name "${repo}" NAME_WE)
    ExternalProject_Add(${name}
        GIT_REPOSITORY
            "${repo}"
        GIT_TAG
            "${tag}"
        GIT_PROGRESS
            ON
        CMAKE_CACHE_ARGS
            ${CMAKE_ARGS}
            ${ARGN}
        CMAKE_GENERATOR
            "Ninja"
    )
endfunction()

function(simple_submodule folder)
    set(folder_path "${CMAKE_CURRENT_SOURCE_DIR}/${folder}")
    if(NOT EXISTS "${folder_path}" OR NOT EXISTS "${folder_path}/CMakeLists.txt")
        message(STATUS "Submodule '${folder}' not initialized, running git...")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --show-toplevel
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE git_root
            OUTPUT_STRIP_TRAILING_WHITESPACE
            COMMAND_ERROR_IS_FATAL ANY
        )
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" submodule update --init
            WORKING_DIRECTORY "${git_root}"
            COMMAND_ERROR_IS_FATAL ANY
        )
    endif()
    ExternalProject_Add(${folder}
        SOURCE_DIR
            "${folder_path}"
        CMAKE_CACHE_ARGS
            ${CMAKE_ARGS}
            ${ARGN}
        CMAKE_GENERATOR
            "Ninja"
        # Always trigger the build step (necessary because there is no download step)
        BUILD_ALWAYS
            ON
    )
endfunction()
