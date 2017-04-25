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

project(remill LANGUAGES)
cmake_minimum_required (VERSION 3.2)

#
# compiler selection
#

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

# llvm
if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
endif ()

if (DEFINED LLVM_INSTALL_PREFIX)
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm/")
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake/")

    message(STATUS "Using LLVM_INSTALL_PREFIX hints for find_package(LLVM): ${FINDPACKAGE_LLVM_HINTS}")
endif ()

# it is important to avoid re-defining these variables if they have been already
# set or you risk ending up in a configure loop!
if (NOT DEFINED CMAKE_C_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
    else ()
        set(CMAKE_C_COMPILER "clang")
    endif ()
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++")
    else ()
        set(CMAKE_CXX_COMPILER "clang++")
    endif ()
endif ()

if (NOT DEFINED CMAKE_ASM_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
    else ()
        set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})
    endif ()
endif ()

if (NOT DEFINED CMAKE_LLVM_LINK)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
    else ()
        set(CMAKE_LLVM_LINK "llvm-link")
    endif ()
endif ()

enable_language(C)
enable_language(CXX)
enable_language(ASM)

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

find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

set(LLVM_LIBRARIES LLVMCore LLVMSupport LLVMAnalysis LLVMipo LLVMIRReader LLVMBitReader LLVMBitWriter LLVMTransformUtils LLVMScalarOpts LLVMLTO)
list(APPEND PROJECT_LIBRARIES ${LLVM_LIBRARIES})

list(APPEND PROJECT_DEFINITIONS ${LLVM_DEFINITIONS})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${LLVM_INCLUDE_DIRS})

# xed
find_package(XED REQUIRED)
list(APPEND PROJECT_LIBRARIES ${XED_LIBRARIES})
list(APPEND PROJECT_INCLUDEDIRECTORIES ${XED_INCLUDE_DIRS})

# google log module
find_package(glog REQUIRED)
list(APPEND PROJECT_LIBRARIES glog::glog)

# gflags
find_package(gflags REQUIRED)
list(APPEND PROJECT_LIBRARIES gflags)

#
# target settings
#

list(APPEND PROJECT_DEFINITIONS "INSTALL_SEMANTICS_DIR=\"${CMAKE_INSTALL_PREFIX}share/remill/semantics/\"")
list(APPEND PROJECT_DEFINITIONS "BUILD_SEMANTICS_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/\"")

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

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since remill-lift includes some files directly
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

# add everything as public; the remill_lift executable will inherit all settings from us
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

#
# install directives
#

install(DIRECTORY DESTINATION "share/remill")

#
# additional targets
#

add_custom_target(semantics)
add_subdirectory(remill/Arch/X86/Runtime)

# mcsema needs to be manually cloned into this repo.
if (EXISTS ${CMAKE_SOURCE_DIR}/tools/mcsema)
    add_subdirectory(tools/mcsema)
endif ()


# only enable tests when compiling under x64
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    if(UNIX AND NOT APPLE)
      set(LINUX TRUE)
      add_subdirectory(tests/X86)
  endif ()
endif ()
