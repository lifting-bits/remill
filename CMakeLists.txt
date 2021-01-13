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

if (NOT DEFINED ENV{TRAILOFBITS_LIBRARIES})
  message(STATUS "Using new vcpkg build system")
  include(CMakeLists_vcpkg.txt)
  return()
endif()

project(remill)
cmake_minimum_required(VERSION 3.14)

include(GNUInstallDirs)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/BCCompiler.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/ccache.cmake")
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")
include(CTest)

if (LLVM_Z3_INSTALL_DIR)
  find_package(Z3 4.7.1)
  set(need_z3 TRUE)
elseif(DEFINED CXX_COMMON_REPOSITORY_ROOT)
  set(LLVM_Z3_INSTALL_DIR "${CXX_COMMON_REPOSITORY_ROOT}/z3" CACHE PATH "Path to the z3 installation")
  set(need_z3 TRUE)
else()
  set(need_z3 FALSE)
endif()

if(need_z3)
  find_package(Z3 4.7.1)
  if (NOT Z3_FOUND)
    message(WARNING "Z3 >= 4.7.1 has not been found in LLVM_Z3_INSTALL_DIR: ${LLVM_Z3_INSTALL_DIR}.")
  endif()
endif()

configureCcache()
FindAndSelectClangCompiler()

enable_language(C CXX ASM)

set(REMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}")

if(DEFINED WIN32)
  set(dynamic_lib_prefix "")
  set(dynamic_lib_extension "dll")
  set(static_lib_prefix "")
  set(static_lib_extension "lib")
  set(executable_extension ".exe")
  set(install_folder "${CMAKE_INSTALL_PREFIX}/remill")
else()
  set(dynamic_lib_prefix "lib")
  set(dynamic_lib_extension "so")
  set(static_lib_prefix "lib")
  set(static_lib_extension "a")
  set(executable_extension "")
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

set(REMILL_INSTALL_LIB_DIR "${install_folder}/lib" CACHE PATH "Directory in which remill libraries will be installed")
set(REMILL_INSTALL_BIN_DIR "${install_folder}/bin" CACHE PATH "Directory in which remill binaries will be installed")
set(REMILL_INSTALL_INCLUDE_DIR "${install_folder}/include" CACHE PATH "Directory in which remill headers will be installed")
set(REMILL_INSTALL_SHARE_DIR "${install_folder}/share" CACHE PATH "Directory in which remill cmake files will be installed")

#
# libraries
#

# LLVM
find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

add_library(thirdparty_llvm INTERFACE)
target_include_directories(thirdparty_llvm SYSTEM INTERFACE
  ${LLVM_INCLUDE_DIRS}
)
target_compile_definitions(thirdparty_llvm INTERFACE
  ${LLVM_DEFINITIONS}
)

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

# Microsoft Z3
add_library(thirdparty_z3 INTERFACE)
if(Z3_FOUND)
  target_include_directories(thirdparty_z3 SYSTEM INTERFACE
    ${Z3_INCLUDE_DIR}
  )
  target_link_libraries(thirdparty_z3 INTERFACE
    ${Z3_LIBRARIES}
  )
endif()

# Intel XED
find_package(XED REQUIRED)
add_library(thirdparty_xed INTERFACE)
target_include_directories(thirdparty_xed SYSTEM INTERFACE
  ${XED_INCLUDE_DIRS}
)
target_link_libraries(thirdparty_xed INTERFACE
  ${XED_LIBRARIES}
)

# Google glog module
find_package(glog REQUIRED)
add_library(thirdparty_glog INTERFACE)
target_link_libraries(thirdparty_glog INTERFACE
  glog::glog
)

# Google gflags
find_package(gflags REQUIRED)
add_library(thirdparty_gflags INTERFACE)
target_link_libraries(thirdparty_gflags INTERFACE
  gflags
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

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION}")
math(EXPR REMILL_LLVM_VERSION_NUMBER "${LLVM_MAJOR_VERSION} * 100 + ${LLVM_MINOR_VERSION}")

if(DEFINED WIN32)
  set(REMILL_INSTALL_SEMANTICS_DIR "${install_folder}/${REMILL_LLVM_VERSION}/semantics" CACHE PATH "Directory into which semantics are installed")
else()
  set(REMILL_INSTALL_SEMANTICS_DIR "${REMILL_INSTALL_SHARE_DIR}/remill/${REMILL_LLVM_VERSION}/semantics" CACHE PATH "Directory into which semantics are installed")
endif()

set(REMILL_BUILD_SEMANTICS_DIR_X86 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/X86/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_AARCH64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/AArch64/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_SPARC32 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC32/Runtime")
set(REMILL_BUILD_SEMANTICS_DIR_SPARC64 "${CMAKE_CURRENT_BINARY_DIR}/lib/Arch/SPARC64/Runtime")

set(REMILL_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(REMILL_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")

add_library(remill_settings INTERFACE)

target_include_directories(remill_settings INTERFACE "${REMILL_INCLUDE_DIR}")

if(WIN32)
  # warnings and compiler settings
  target_compile_options(remill_settings INTERFACE
    /MD /nologo /W3 /EHsc /wd4141 /wd4146 /wd4180 /wd4244
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
  "REMILL_INSTALL_SEMANTICS_DIR=\"${REMILL_INSTALL_SEMANTICS_DIR}/\""
  "REMILL_BUILD_SEMANTICS_DIR_X86=\"${REMILL_BUILD_SEMANTICS_DIR_X86}\""
  "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH64}\""
  "REMILL_BUILD_SEMANTICS_DIR_SPARC32=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC32}\""
  "REMILL_BUILD_SEMANTICS_DIR_SPARC64=\"${REMILL_BUILD_SEMANTICS_DIR_SPARC64}\""
)

set(THIRDPARTY_LIBRARY_LIST thirdparty_z3
  thirdparty_llvm
  thirdparty_xed
  thirdparty_glog
  thirdparty_gflags)

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

set(INSTALLED_CLANG_NAME "remill-clang-${REMILL_LLVM_VERSION}${executable_extension}")
set(INSTALLED_LLVMLINK_NAME "remill-llvm-link-${REMILL_LLVM_VERSION}${executable_extension}")

if("${CXX_COMMON_REPOSITORY_ROOT}" STREQUAL "" OR NOT EXISTS "${CXX_COMMON_REPOSITORY_ROOT}/llvm")
  set(INSTALLED_LIBLLVM_NAME "${dynamic_lib_prefix}LLVM-${REMILL_LLVM_VERSION}.${dynamic_lib_extension}")

  # system binaries are not built statically, so we need to fix the rpath
  find_program("clang_location" "clang-${REMILL_LLVM_VERSION}${executable_extension}")
  if("${clang_location}" STREQUAL "clang_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the clang executable")
  endif()

  message("InstallExternalTarget: Found clang executable: ${clang_location}")

  find_program("llvmlink_location" "llvm-link${executable_extension}")
  if("${llvmlink_location}" STREQUAL "llvmlink_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the llvm-link executable")
  endif()

  message("InstallExternalTarget: Found llvm-link executable: ${llvmlink_location}")

  find_library("libllvm_location" "${dynamic_lib_prefix}LLVM-${REMILL_LLVM_VERSION}.${dynamic_lib_extension}")
  if("${libllvm_location}" STREQUAL "libllvm_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the libLLVM dynamic library")
  endif()
  
  message("InstallExternalTarget: Found libLLVM location: ${libllvm_location}")

  InstallExternalTarget("ext_clang" "${clang_location}" "${REMILL_INSTALL_BIN_DIR}"
    "${INSTALLED_CLANG_NAME}" "${REMILL_INSTALL_LIB_DIR}")

  InstallExternalTarget("ext_llvmlink" "${llvmlink_location}" "${REMILL_INSTALL_BIN_DIR}"
    "${INSTALLED_LLVMLINK_NAME}" "${REMILL_INSTALL_LIB_DIR}")

else()
  # The executable in our binary repository are statically built, meaning that we don't need
  # to change the rpath
  InstallExternalTarget("ext_clang" "${CXX_COMMON_REPOSITORY_ROOT}/llvm/bin/clang${executable_extension}"
    "${REMILL_INSTALL_BIN_DIR}" "${INSTALLED_CLANG_NAME}")

  InstallExternalTarget("ext_llvmlink" "${CXX_COMMON_REPOSITORY_ROOT}/llvm/bin/llvm-link${executable_extension}"
    "${REMILL_INSTALL_BIN_DIR}" "${INSTALLED_LLVMLINK_NAME}")
endif()

set(REMILL_BC_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_bc.${static_lib_extension}")
set(REMILL_ARCH_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_arch.${static_lib_extension}")
set(REMILL_ARCH_X86_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_arch_x86.${static_lib_extension}")
set(REMILL_ARCH_AARCH64_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_arch_aarch64.${static_lib_extension}")
set(REMILL_ARCH_SPARC32_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_arch_sparc32.${static_lib_extension}")
set(REMILL_ARCH_SPARC64_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_arch_sparc64.${static_lib_extension}")
set(REMILL_OS_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_os.${static_lib_extension}")
set(REMILL_VERSION_LIBRARY_LOCATION "${REMILL_INSTALL_LIB_DIR}/${static_lib_prefix}remill_version.${static_lib_extension}")


set(REMILL_INCLUDE_LOCATION "${REMILL_INSTALL_INCLUDE_DIR}")
get_target_property(REMILL_COMPILE_OPTIONS remill_settings INTERFACE_COMPILE_OPTIONS)
get_target_property(REMILL_COMPILE_DEFINITIONS remill_settings INTERFACE_COMPILE_DEFINITIONS)

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

# First do the basic substitutions.
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/remillConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake.pregen"
  @ONLY
)

# Then expand the generator expressions added to `THIRDPARTY_LIBRARY_FILES`.
file(GENERATE
  OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake"
  INPUT "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake.pregen"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/remillConfig.cmake"
  DESTINATION "${REMILL_INSTALL_LIB_DIR}/cmake/remill"
)

install(DIRECTORY "${REMILL_INCLUDE_DIR}/remill"
  DESTINATION "${REMILL_INSTALL_INCLUDE_DIR}"
)

#
# additional targets
#

add_custom_target(semantics)

# tools
add_subdirectory(bin)

# tests
if ("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  add_custom_target(test_dependencies)

  if(NOT "${PLATFORM_NAME}" STREQUAL "windows")
    if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "AMD64" OR "${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
      message(STATUS "X86 tests enabled")
      add_subdirectory(tests/X86)
    endif()
  endif()

  if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64" AND "${PLATFORM_NAME}" STREQUAL "linux")
    message(STATUS "aarch64 tests enabled")
    add_subdirectory(tests/AArch64)
  endif()
endif()
