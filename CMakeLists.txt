# Copyright (c) 2018 Trail of Bits, Inc.
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

cmake_minimum_required(VERSION 3.21)
include(cmake/vcpkg_helper.cmake)

# Setup to use ccache
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccache.cmake")

project(remill C CXX ASM)
include(GNUInstallDirs)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

if(REMILL_ENABLE_TESTING)
  include(CTest)
endif()

message(STATUS "Compiler ID is ${CMAKE_C_COMPILER_ID}")

#
# libraries
#

# LLVM
find_package(LLVM CONFIG REQUIRED)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

set(LLVM_MAJOR_VERSION "${LLVM_MAJOR_VERSION}")
set(LLVM_MINOR_VERSION "${LLVM_MINOR_VERSION}")

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}")

message("Remill llvm version: ${REMILL_LLVM_VERSION}")
set(REMILL_INSTALL_SEMANTICS_DIR "${CMAKE_INSTALL_PREFIX}/${REMILL_INSTALL_SHARE_DIR}/remill/${REMILL_LLVM_VERSION}/semantics" CACHE PATH "Directory into which semantics are installed")
set(REMILL_BUILD_SEMANTICS_DIR_X86 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/X86/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_AARCH32 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/AArch32/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_AARCH64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/AArch64/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_SPARC32 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC32/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_SPARC64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC64/Runtime")
set(REMILL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(REMILL_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")

add_library(thirdparty_llvm INTERFACE)
target_include_directories(thirdparty_llvm SYSTEM INTERFACE
  $<BUILD_INTERFACE:${LLVM_INCLUDE_DIRS}>
)
target_compile_definitions(thirdparty_llvm INTERFACE
  ${LLVM_DEFINITIONS}
)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/BCCompiler.cmake")

# Go find only the static libraries of LLVM, and link against those.
foreach(LLVM_LIB IN LISTS LLVM_AVAILABLE_LIBS)
  get_target_property(LLVM_LIB_TYPE ${LLVM_LIB} TYPE)
  if(LLVM_LIB_TYPE STREQUAL "STATIC_LIBRARY")
    list(APPEND LLVM_LIBRARIES "${LLVM_LIB}")
  endif()
endforeach()

# These are out-of-order in `LLVM_AVAILABLE_LIBS` and should always be last.
list(REMOVE_ITEM LLVM_LIBRARIES LLVMMC LLVMCore LLVMSupport)
list(APPEND LLVM_LIBRARIES LLVMMC LLVMCore LLVMSupport)

target_link_libraries(thirdparty_llvm INTERFACE
  ${LLVM_LIBRARIES}
)

# Microsoft Z3 with LLVM. Not exactly used in remill, but LLVM doesn't link
# against it correctly
# NOTE: If changing this, also replicate in remillConfig file
if (LLVM_WITH_Z3)
  find_package(Z3 CONFIG REQUIRED 4.7.1)
  get_target_property(LLVMSupport_LIBS LLVMSupport INTERFACE_LINK_LIBRARIES)
  list(REMOVE_ITEM LLVMSupport_LIBS Z3)
  list(APPEND LLVMSupport_LIBS z3::libz3)
  set_target_properties(LLVMSupport PROPERTIES
    INTERFACE_LINK_LIBRARIES "${LLVMSupport_LIBS}")
endif()

message(STATUS "LLVM Libraries: ${LLVM_LIBRARIES}")

# Intel XED
find_package(XED CONFIG REQUIRED)
add_library(thirdparty_xed INTERFACE)
target_link_libraries(thirdparty_xed INTERFACE
  XED::XED
)

# Google glog module
find_package(glog CONFIG REQUIRED)
add_library(thirdparty_glog INTERFACE)
target_link_libraries(thirdparty_glog INTERFACE
  glog::glog
)

# Google gflags
find_package(gflags CONFIG REQUIRED)
add_library(thirdparty_gflags INTERFACE)
target_link_libraries(thirdparty_gflags INTERFACE
  gflags
)

# GHIDRA SLEIGH
find_package(sleigh CONFIG REQUIRED)
add_library(thirdparty_sleigh INTERFACE)
target_link_libraries(thirdparty_sleigh INTERFACE
  sleigh::sla
  sleigh::decomp
  sleigh::support
)

# Windows SDK
add_library(thirdparty_win32 INTERFACE)
if(DEFINED WIN32)
  target_link_libraries(thirdparty_win32 INTERFACE
     "Kernel32.lib"
  )
endif()


# For Linux builds, group LLVM libraries into a single group
# that avoids frustrating library ordering issues.
if(UNIX AND NOT APPLE)
  set(LINKER_START_GROUP "-Wl,--start-group")
  set(LINKER_END_GROUP "-Wl,--end-group")
else()
  set(LINKER_START_GROUP "")
  set(LINKER_END_GROUP "")
endif()

#
# Configuration options for semantics
#
option(REMILL_BARRIER_AS_NOP "Remove compiler barriers (inline assembly) in semantics" OFF)
option(REMILL_BUILD_SPARC32_RUNTIME "Build the Runtime for SPARC32. Turn this off if you have include errors with <bits/c++config.h>, or read the README for a fix" ON)

#
# target settings
#

# add everything as public.

add_library(remill_settings INTERFACE)

target_include_directories(remill_settings INTERFACE
  $<BUILD_INTERFACE:${REMILL_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include>)

if(WIN32)
  # warnings and compiler settings
  target_compile_options(remill_settings INTERFACE
    "$<$<CONFIG:Debug>:/MDd>$<$<CONFIG:Release>:/MD>"
    /nologo /W3 /EHsc /wd4141 /wd4146 /wd4180 /wd4244
    /wd4258 /wd4267 /wd4291 /wd4345 /wd4351 /wd4355 /wd4456
    /wd4457 /wd4458 /wd4459 /wd4503 /wd4624 /wd4722 /wd4800
    /wd4100 /wd4127 /wd4512 /wd4505 /wd4610 /wd4510 /wd4702
    /wd4245 /wd4706 /wd4310 /wd4701 /wd4703 /wd4389 /wd4611
    /wd4805 /wd4204 /wd4577 /wd4091 /wd4592 /wd4324
  )

  target_compile_definitions(remill_settings INTERFACE
    _CRT_SECURE_NO_DEPRECATE
    _CRT_SECURE_NO_WARNINGS
    _CRT_NONSTDC_NO_DEPRECATE
    _CRT_NONSTDC_NO_WARNINGS
    _SCL_SECURE_NO_DEPRECATE
    _SCL_SECURE_NO_WARNINGS
    GOOGLE_PROTOBUF_NO_RTTI
  )

else()
  # warnings and compiler settings
  target_compile_options(remill_settings INTERFACE
    -Wall -Wextra -Wno-unused-parameter -Wno-c++98-compat
    -Wno-unreachable-code-return -Wno-nested-anon-types
    -Wno-extended-offsetof
    -Wno-variadic-macros -Wno-return-type-c-linkage
    -Wno-c99-extensions -Wno-ignored-attributes -Wno-unused-local-typedef
    -Wno-unknown-pragmas -Wno-unknown-warning-option -fPIC
    -fno-omit-frame-pointer -fvisibility-inlines-hidden
    -fno-asynchronous-unwind-tables
  )

  # Clang-specific warnings/error options
  if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    target_compile_options(remill_settings INTERFACE
      -Wgnu-alignof-expression -Wno-gnu-anonymous-struct -Wno-gnu-designator
      -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression
      -fno-aligned-allocation
    )
  endif()

  # debug symbols
  if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(remill_settings INTERFACE
      -gdwarf-2 -g3
    )
  endif()

  # optimization flags and definitions
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(remill_settings INTERFACE
      -O0
    )
    target_compile_definitions(remill_settings INTERFACE
      "DEBUG"
    )
  else()
    target_compile_options(remill_settings INTERFACE
      -O2
    )
    target_compile_definitions(remill_settings INTERFACE
      "NDEBUG"
    )
  endif()
endif()

target_compile_definitions(remill_settings INTERFACE
  "REMILL_INSTALL_SEMANTICS_DIR=\"${REMILL_INSTALL_SEMANTICS_DIR}\""
  "REMILL_BUILD_SEMANTICS_DIR_X86=\"${REMILL_BUILD_SEMANTICS_DIR_X86}\""
  "REMILL_BUILD_SEMANTICS_DIR_AARCH32=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH32}\""
  "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH64}\""
  "REMILL_BUILD_SEMANTICS_DIR_SPARC32=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC32}\""
  "REMILL_BUILD_SEMANTICS_DIR_SPARC64=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC64}\""
)

set(THIRDPARTY_LIBRARY_LIST thirdparty_llvm thirdparty_xed thirdparty_glog thirdparty_gflags thirdparty_sleigh)
target_link_libraries(remill_settings INTERFACE
  ${THIRDPARTY_LIBRARY_LIST}
)

add_subdirectory(lib/Arch)
add_subdirectory(lib/BC)
add_subdirectory(lib/OS)
add_subdirectory(lib/Version)

add_library(remill INTERFACE)
target_link_libraries(remill INTERFACE
  ${LINKER_START_GROUP}
  ${THIRDPARTY_LIBRARY_LIST}
  remill_bc
  remill_os
  remill_arch
  remill_version
  ${LINKER_END_GROUP}
)

#
# Also install clang, libllvm and llvm-link
#

set(INSTALLED_CLANG_NAME "remill-clang-${REMILL_LLVM_VERSION}${CMAKE_EXECUTABLE_SUFFIX}")
set(INSTALLED_LLVMLINK_NAME "remill-llvm-link-${REMILL_LLVM_VERSION}${CMAKE_EXECUTABLE_SUFFIX}")

InstallExternalTarget("ext_clang" "${CLANG_PATH}" "BIN" "${INSTALLED_CLANG_NAME}")

InstallExternalTarget("ext_llvmlink" "${LLVMLINK_PATH}" "BIN" "${INSTALLED_LLVMLINK_NAME}")

GetTargetTree(THIRDPARTY_LIBRARIES ${THIRDPARTY_LIBRARY_LIST})
GetPublicIncludeFolders(THIRDPARTY_INCLUDE_DIRECTORIES ${THIRDPARTY_LIBRARIES})
foreach(THIRDPARTY_LIB IN LISTS THIRDPARTY_LIBRARIES)
  string(SUBSTRING "${THIRDPARTY_LIB}" 0 1 THIRDPARTY_LIB_PREFIX)
  if(TARGET ${THIRDPARTY_LIB})
    get_target_property(THIRDPARTY_LIB_TYPE ${THIRDPARTY_LIB} TYPE)
    if(THIRDPARTY_LIB_TYPE STREQUAL "STATIC_LIBRARY" OR THIRDPARTY_LIB_TYPE STREQUAL "SHARED_LIBRARY")
      list(APPEND THIRDPARTY_LIBRARY_FILES "$${}<TARGET_FILE:${THIRDPARTY_LIB}>")
    endif()
  elseif("${THIRDPARTY_LIB_PREFIX}" STREQUAL "$${}")
    # E.g. $<LINK_ONLY:...>
  else()
    list(APPEND THIRDPARTY_LIBRARY_FILES "${THIRDPARTY_LIB}")
  endif()
endforeach()

list(REMOVE_DUPLICATES THIRDPARTY_LIBRARY_FILES)

#
# additional targets
#

add_custom_target(semantics)

# tools
add_subdirectory(bin)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(TARGETS remill EXPORT remillTargets)
  
  install(TARGETS remill_settings ${THIRDPARTY_LIBRARY_LIST}
    EXPORT remillTargets
  )
  
  # First do the basic substitutions.
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/remillConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake"
    @ONLY
  )
  
  install(FILES "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake"
                "${CMAKE_CURRENT_LIST_DIR}/cmake/vcpkg_helper.cmake"
    DESTINATION "${REMILL_INSTALL_LIB_DIR}/cmake/remill"
  )
  
  install(DIRECTORY "${REMILL_INCLUDE_DIR}/remill/"
    DESTINATION "${REMILL_INSTALL_INCLUDE_DIR}/remill"
  )

  install(EXPORT remillTargets
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/remill")
endif()

# tests
if (REMILL_ENABLE_TESTING)
  # Tests require enabling exports on binaries
  # https://cmake.org/cmake/help/latest/variable/CMAKE_ENABLE_EXPORTS.html#variable:CMAKE_ENABLE_EXPORTS
  set(CMAKE_ENABLE_EXPORTS ON)

  find_package(Threads REQUIRED)
  add_custom_target(test_dependencies)

  if(REMILL_ENABLE_TESTING_X86)
    message(STATUS "X86 tests enabled")
    add_subdirectory(tests/X86)
  endif()

  if(REMILL_ENABLE_TESTING_AARCH64)
    message(STATUS "aarch64 tests enabled")
    add_subdirectory(tests/AArch64)
  endif()
endif()
