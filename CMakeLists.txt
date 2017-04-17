# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.
project(remill LANGUAGES C CXX ASM)
cmake_minimum_required (VERSION 3.2)

if (NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Remill is only supported on 64-bit architectures.")
endif ()

#
# compiler selection
#

if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
endif ()

if (DEFINED LLVM_INSTALL_PREFIX)
    set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")

    set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang-3.9")
    set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang-3.9")
    set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang-3.9")
endif ()

if (NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER "clang")
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER "clang++")
endif ()

if (NOT DEFINED CMAKE_ASM_COMPILER)
    set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})
endif ()

if (NOT DEFINED CMAKE_LLVM_LINK)
    set(CMAKE_LLVM_LINK "llvm-link")
endif ()

#
# compiler settings
#

# enable the gnu extensions
set(CMAKE_CXX_EXTENSIONS ON)

# visual studio already defaults to c++11
if (NOT WIN32)
    set(CMAKE_CXX_STANDARD 11)
endif ()

# warnings and compiler settings
set(PROJECT_CXXWARNINGS "-Wall -Wextra -Werror -pedantic -Wno-unused-parameter -Wno-c++98-compat -Wno-unreachable-code-return -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-anonymous-struct -Wno-gnu-designator -Wno-variadic-macros -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression -Wno-return-type-c-linkage -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef")
set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -Wno-unknown-warning-option ${PROJECT_CXXWARNINGS} -fPIC -fno-omit-frame-pointer -fvisibility-inlines-hidden -fno-exceptions -fno-asynchronous-unwind-tables -fno-rtti")

# default build type
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif ()

# debug symbols
if (CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -gdwarf-2 -g3")
endif ()

# optimization flags and definitions
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -O0")
else ()
    set(PROJECT_CXXFLAGS "${PROJECT_CXXFLAGS} -O3")
    list(APPEND PROJECT_DEFINITIONS "NDEBUG")
endif ()

#
# libraries
#

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

# llvm
find_package(LLVM 3.9 REQUIRED CONFIG)

llvm_map_components_to_libnames(LLVM_LIBRARIES support core irreader ipo bitreader bitwriter analysis transformutils lto scalaropts)
list(APPEND PROJECT_LIBRARIES ${LLVM_LIBRARIES})

list(APPEND PROJECT_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

# xed
find_package(XED REQUIRED)
list(APPEND PROJECT_LIBRARIES ${XED_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${XED_INCLUDE_DIRS})

# google gtest
find_package(gtest REQUIRED)
list(APPEND PROJECT_LIBRARIES ${gtest_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${gtest_INCLUDE_DIRS})

# google log module
find_package(glog REQUIRED)
list(APPEND PROJECT_LIBRARIES glog::glog)

# gflags
find_package(gflags REQUIRED)
list(APPEND PROJECT_LIBRARIES gflags)

# protobuf
find_package(Protobuf REQUIRED)
list(APPEND PROJECT_LIBRARIES ${Protobuf_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${Protobuf_INCLUDE_DIR})
list(APPEND PROJECT_DEFINITIONS "GOOGLE_PROTOBUF_NO_RTTI")

#
# protobuf file generation 
#

# this function can't be told where to store the output files! we have to add the whole binary directory
# to the include directories (or change it and lose compatibility with the system libraries)
protobuf_generate_cpp(PROJECT_PROTOBUFSOURCEFILES PROJECT_PROTOBUFHEADERFILES "${CMAKE_SOURCE_DIR}/remill/CFG/CFG.proto")
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate_python(PROJECT_PROTOBUFPYTHONMODULE "${CMAKE_SOURCE_DIR}/remill/CFG/CFG.proto")
add_custom_target(protobuf_python_module DEPENDS ${PROJECT_PROTOBUFPYTHONMODULE})

#
# target settings
#

list(APPEND PROJECT_DEFINITIONS "INSTALL_SEMANTICS_DIR=\"${CMAKE_INSTALL_PREFIX}/share/remill/semantics/\"")
list(APPEND PROJECT_DEFINITIONS "BUILD_SEMANTICS_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/\"")

add_library(${PROJECT_NAME} STATIC
    remill/Arch/X86/Arch.cpp
    remill/Arch/Arch.cpp
    remill/Arch/Instruction.cpp
    remill/Arch/Name.cpp

    remill/CFG/BlockHasher.cpp
    remill/CFG/CFG.cpp

    remill/BC/IntrinsicTable.cpp
    remill/BC/Lifter.cpp
    remill/BC/Optimizer.cpp
    remill/BC/Util.cpp

    remill/OS/FileSystem.cpp
    remill/OS/OS.cpp

    third_party/murmurhash/MurmurHash2.cpp

    ${PROJECT_PROTOBUFSOURCEFILES}
    ${PROJECT_PROTOBUFHEADERFILES}
)

add_dependencies(${PROJECT_NAME} protobuf_python_module)

# add everything as public; the remill_lift executable will inherit all settings from us
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since remill-lift includes some files directly
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

#
# install directives
#

install(DIRECTORY "${CMAKE_SOURCE_DIR}/tools/remill_disass" DESTINATION "usr/share/remill/disassembler")
install(FILES "${CMAKE_SOURCE_DIR}/tools/setup.py" DESTINATION "usr/share/remill/disassembler")
install(FILES "${PROJECT_PROTOBUFPYTHONMODULE}" DESTINATION "usr/share/remill/disassembler/remill_disass")

#
# additional targets
#

add_custom_target(semantics)

add_subdirectory(remill/Arch/X86/Runtime)
add_subdirectory(tools)
add_subdirectory(tests/X86)
