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
cmake_minimum_required(VERSION 3.1)

if(WIN32)
  string(REGEX REPLACE "\\\\" "/" CMAKE_PROJECT_DIR "${CMAKE_PROJECT_DIR}")
  string(REGEX REPLACE "\\\\" "/" CMAKE_BINARY_DIR "${CMAKE_BINARY_DIR}")
  SET(CMAKE_EXE_LINKER_FLAGS "/LARGEADDRESSAWARE ${CMAKE_EXE_LINKER_FLAGS}")
else()
  # WIN32 defaults to CXX11 by default, and setting it explicitly
  # confuses clang-cl, which will bail out with "unknown flag -std=g++11"
  # So only set this value for non-Win32 targets
  set(CMAKE_CXX_STANDARD 11)
endif()

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

enable_language(ASM)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gflags")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/glog")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/googletest")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_ROOT}/Modules")

# Get google flags.
include (${PROJECT_SOURCE_DIR}/cmake/gflags/CMakeLists.txt)
set(GFLAGS_INCLUDE_DIRS "${GFLAGS_ROOT}/src")
set(GFLAGS_LIBRARIES "$<TARGET_FILE:libgflags>")

# Get google log.
include (${PROJECT_SOURCE_DIR}/cmake/glog/CMakeLists.txt)
set(GLOG_INCLUDE_DIRS "${GLOG_ROOT}/src")
set(GLOG_LIBRARIES "$<TARGET_FILE:libglog>")

# If we're on 64-bit linux then bring in the testing stuff, *then* enable
# CTest (so as to avoid building the test cases of gflags and glog.)
if(LINUX AND CMAKE_SIZEOF_VOID_P EQUAL 8)
  # Get google test.
  include (${PROJECT_SOURCE_DIR}/cmake/googletest/CMakeLists.txt)
  set(GTEST_INCLUDE_DIRS "${GTEST_ROOT}/src")
  set(GTEST_LIBRARIES "$<TARGET_FILE:libgtest>")
  include(CTest)
endif()

# Find LLVM.
set(LLVM_INSTALL_PREFIX /data/llvm-3.9/install)
find_package(LLVM REQUIRED CONFIG HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake" "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm")
add_definitions(${LLVM_DEFINITIONS})
include (LLVMUtils)


include_directories("${GLOG_INCLUDE_DIRS}")
include_directories("${GFLAGS_INCLUDE_DIRS}")

#find_package(XED REQUIRED)
#find_package(GLOG REQUIRED)
#find_package(GFLAGS REQUIRED)
#
#include_directories("${PROJECT_SOURCE_DIR}")
#include_directories("${LLVM_INCLUDE_DIRS}")
#include_directories("${XED_INCLUDE_DIRS}")
#include_directories("${CMAKE_CURRENT_LIST_DIR}")
#
#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")
#
#if(NOT DEFINED CMAKE_C_COMPILER)
#    set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang")
#endif()
#
#if(NOT DEFINED CMAKE_CXX_COMPILER)
#    set(CMAKE_CXX_COMPILER ${CMAKE_C_COMPILER})
#endif()
#
#if(NOT DEFINED CMAKE_ASM_COMPILER)
#    set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
#endif()
#
#if(NOT DEFINED CMAKE_LLVM_LINK)
#    set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
#endif()
#

#
#if(NOT DEFINED PYTHON_PATH)
#    set(PYTHON_PATH python)
#endif()
#
#if(NOT WIN32)
#  add_compile_options(
#    -g3
#    -O0
#    -std=gnu++11)
#
#  if(NOT LLVM_ENABLE_RTTI)
#    add_compile_options(
#      -fno-rtti
#      -DGOOGLE_PROTOBUF_NO_RTTI)
#  endif()
#endif(WIN32)
#
## Clang-specific compiler options.
#add_compile_options(
#  -Wall
#  -Wextra
#  -Werror
#  -pedantic
#  
#  # We support multiple versions of Clang/LLVM, so if one version supports
#  # a flag but not another then don't warn about it.  
#  -Wno-unknown-warning-option
#
#  -Wno-unused-parameter
#  -Wno-c++98-compat
#  -Wno-unreachable-code-return
#  -Wno-nested-anon-types
#  -Wno-extended-offsetof
#  -Wno-gnu-anonymous-struct
#  -Wno-gnu-designator
#  -Wno-variadic-macros
#  -Wno-gnu-zero-variadic-macro-arguments
#  -Wno-gnu-statement-expression
#  -Wno-return-type-c-linkage
#  -Wno-c99-extensions
#  -Wno-ignored-attributes
#  -Wno-unused-local-typedef
#  
#  -fno-omit-frame-pointer
#  -fvisibility-inlines-hidden
#
#  -DINSTALL_SEMANTICS_DIR="${CMAKE_INSTALL_PREFIX}/share/remill/semantics/"
#  -DBUILD_SEMANTICS_DIR="${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/"
#  -DGOOGLE_PROTOBUF_NO_RTTI
#)
#
#add_library(remill STATIC
#  remill/Arch/X86/Arch.cpp
#  remill/Arch/Arch.cpp
#  remill/Arch/Instruction.cpp
#  remill/Arch/Name.cpp
#  remill/BC/IntrinsicTable.cpp
#  remill/BC/Lifter.cpp
#  remill/BC/Optimizer.cpp
#  remill/BC/Util.cpp
#  remill/OS/FileSystem.cpp
#  remill/OS/OS.cpp
#)
#
#target_link_libraries(remill
#  ${GFLAGS_LIBRARIES}
#  ${GLOG_LIBRARIES}
#  ${XED_LIBRARIES}
#  LLVMCore
#  LLVMSupport
#  LLVMAnalysis
#  LLVMipo
#  LLVMIRReader
#  LLVMBitReader
#  LLVMBitWriter
#  LLVMTransformUtils
#  LLVMScalarOpts
#  LLVMLTO
#)
#
#install(
#  TARGETS remill
#  ARCHIVE DESTINATION lib
#)
#
#add_custom_target(semantics)
#add_subdirectory(remill/Arch/X86/Runtime)
#add_subdirectory(tools)

# Only build tests on a 64-bit Linux.
if(BUILD_TESTING)
  add_subdirectory(tests/X86)
endif(BUILD_TESTING)
