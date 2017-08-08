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

project(remill)
cmake_minimum_required (VERSION 3.2)

# add the BC (bitcode) language definition
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/BCCompiler")

include(CTest)

set(REMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")

#
# compiler selection
#

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES}
        CACHE PATH "Location of cxx-common libraries.")
endif ()

if (DEFINED LIBRARY_REPOSITORY_ROOT)
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
enable_language(BC)

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
set(PROJECT_CXXWARNINGS "-Wall -Wextra -Wno-unused-parameter -Wno-c++98-compat -Wno-unreachable-code-return -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-anonymous-struct -Wno-gnu-designator -Wno-variadic-macros -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression -Wno-return-type-c-linkage -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef -Wno-unknown-pragmas")
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


# Split out the LLVM version.
string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION}")

#
# target settings
#

list(APPEND PROJECT_DEFINITIONS "REMILL_INSTALL_SEMANTICS_DIR=\"${CMAKE_INSTALL_PREFIX}/share/remill/${REMILL_LLVM_VERSION}/semantics/\"")
list(APPEND PROJECT_DEFINITIONS "REMILL_BUILD_SEMANTICS_DIR_X86=\"${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/\"")
list(APPEND PROJECT_DEFINITIONS "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/AArch64/Runtime/\"")

add_library(${PROJECT_NAME} STATIC

    remill/Arch/AArch64/Arch.cpp
    remill/Arch/AArch64/Decode.cpp
    remill/Arch/AArch64/Extract.cpp
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
# also be set to PUBLIC since sub-tools of remill include remill's headers directly.
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

#
# additional targets
#

add_custom_target(semantics)

# runtimes
add_subdirectory(remill/Arch/X86/Runtime)
add_subdirectory(remill/Arch/AArch64/Runtime)

# tools
add_subdirectory(tools)

if(UNIX AND NOT APPLE)
  set(LINUX TRUE)
else()
  set(LINUX FALSE)
endif ()

if (LINUX)
  if (CMAKE_SIZEOF_VOID_P EQUAL 8)
  
    # only enable x86 tests when compiling under x64
    if ("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
      add_subdirectory(tests/X86)
    endif ()
    
    # only enable aarch64 tests when compiling under aarch64.
    if ("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
      add_subdirectory(tests/AArch64)
    endif ()
    
  endif ()
endif (LINUX)
