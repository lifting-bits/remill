# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(REMILL LANGUAGES C CXX ASM)
cmake_minimum_required (VERSION 3.2)

#
# compiler selection
#

if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
endif ()

if (DEFINED LLVM_INSTALL_PREFIX)
    set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
    set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
    set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++")
    set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
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
find_package(LLVM REQUIRED CONFIG)

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
# target settings
#

list(APPEND PROJECT_DEFINITIONS "INSTALL_SEMANTICS_DIR=\"${CMAKE_INSTALL_PREFIX}share/remill/semantics/\"")
list(APPEND PROJECT_DEFINITIONS "BUILD_SEMANTICS_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/\"")

MESSAGE(STATUS "DEBUG: ${CMAKE_INSTALL_PREFIX}share/remill/semantics")

add_library(${PROJECT_NAME} STATIC
    remill/Arch/X86/Arch.cpp
    remill/Arch/Arch.cpp
    remill/Arch/Instruction.cpp
    remill/Arch/Name.cpp

    remill/BC/IntrinsicTable.cpp
    remill/BC/Lifter.cpp
    remill/BC/Util.cpp

    remill/OS/FileSystem.cpp
    remill/OS/OS.cpp
)

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

install(DIRECTORY DESTINATION "share/remill")
install(DIRECTORY DESTINATION "share/remill/disassembler")

#
# additional targets
#

add_custom_target(semantics)

add_subdirectory(remill/Arch/X86/Runtime)
add_subdirectory(tools)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(UNIX AND NOT APPLE)
      set(LINUX TRUE)
      add_subdirectory(tests/X86)
  endif ()
endif ()