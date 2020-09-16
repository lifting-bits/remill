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

# Fix behavior of CMAKE_CXX_STANDARD when targeting macOS.
if (POLICY CMP0025)
  cmake_policy(SET CMP0025 NEW)
endif ()

project(remill)
cmake_minimum_required(VERSION 3.2)

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
  set(LLVM_Z3_INSTALL_DIR "${CXX_COMMON_REPOSITORY_ROOT}/z3")
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
  set(executable_extension ".exe")
  set(install_folder "${CMAKE_INSTALL_PREFIX}/remill")
else()
  set(dynamic_lib_prefix "lib")
  set(dynamic_lib_extension "so")
  set(executable_extension "")
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

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
message(WARNING "Libraries: ${LLVM_LIBRARIES}")


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

#
# Configuration options for semantics
#
option(REMILL_BARRIER_AS_NOP "Remove compiler barriers (inline assembly) in semantics" OFF)

#
# target settings
#

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION}")
math(EXPR REMILL_LLVM_VERSION_NUMBER "${LLVM_MAJOR_VERSION} * 100 + ${LLVM_MINOR_VERSION}")

if(DEFINED WIN32)
  set(REMILL_INSTALL_SEMANTICS_DIR "${install_folder}/${REMILL_LLVM_VERSION}/semantics/")
else()
  set(REMILL_INSTALL_SEMANTICS_DIR "${install_folder}/share/remill/${REMILL_LLVM_VERSION}/semantics/")
endif()

set(REMILL_BUILD_SEMANTICS_DIR_X86 "${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/X86/Runtime/")
set(REMILL_BUILD_SEMANTICS_DIR_AARCH64 "${CMAKE_CURRENT_BINARY_DIR}/remill/Arch/AArch64/Runtime/")

# verion data
add_subdirectory(remill/Version)

add_library(remill STATIC
  remill/Arch/AArch64/Arch.cpp
  remill/Arch/AArch64/Decode.cpp
  remill/Arch/AArch64/Extract.cpp
  remill/Arch/X86/Arch.cpp

  remill/Arch/Arch.cpp
  remill/Arch/Instruction.cpp
  remill/Arch/Name.cpp

  remill/BC/Annotate.cpp
  remill/BC/DeadStoreEliminator.cpp
  remill/BC/IntrinsicTable.cpp
  remill/BC/Lifter.cpp
  remill/BC/Optimizer.cpp
  remill/BC/Util.cpp

  remill/OS/Compat.cpp
  remill/OS/FileSystem.cpp
  remill/OS/OS.cpp
)

set_property(TARGET remill PROPERTY POSITION_INDEPENDENT_CODE ON)
set(THIRDPARTY_LIBRARY_LIST thirdparty_z3 thirdparty_llvm thirdparty_xed thirdparty_glog thirdparty_gflags)

# add everything as public.

if(UNIX AND NOT APPLE)
  #For Linux builds, group LLVM libraries into a single group
  # that avoids frustrating library ordering issues
  set(LINKER_START_GROUP "-Wl,--start-group")
  set(LINKER_END_GROUP "-Wl,--end-group")
else()
  set(LINKER_START_GROUP "")
  set(LINKER_END_GROUP "")
endif()


target_link_libraries(remill LINK_PUBLIC
  ${LINKER_START_GROUP} ${THIRDPARTY_LIBRARY_LIST} ${LINKER_END_GROUP}
  RemillVersion
)

target_include_directories(remill PUBLIC ${CMAKE_SOURCE_DIR})

if(WIN32)
  # warnings and compiler settings
  target_compile_options(remill PUBLIC
    /MD /nologo /W3 /EHsc /wd4141 /wd4146 /wd4180 /wd4244
    /wd4258 /wd4267 /wd4291 /wd4345 /wd4351 /wd4355 /wd4456
    /wd4457 /wd4458 /wd4459 /wd4503 /wd4624 /wd4722 /wd4800
    /wd4100 /wd4127 /wd4512 /wd4505 /wd4610 /wd4510 /wd4702
    /wd4245 /wd4706 /wd4310 /wd4701 /wd4703 /wd4389 /wd4611
    /wd4805 /wd4204 /wd4577 /wd4091 /wd4592 /wd4324
  )

  target_compile_definitions(remill PUBLIC
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
  target_compile_options(remill PUBLIC
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
    target_compile_options(remill PUBLIC
      -Wgnu-alignof-expression -Wno-gnu-anonymous-struct -Wno-gnu-designator
      -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-statement-expression
      -fno-aligned-allocation
    )
  endif()

  # debug symbols
  if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(remill PUBLIC
      -gdwarf-2 -g3
    )
  endif()

  # optimization flags and definitions
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(remill PUBLIC
      -O0
    )
    target_compile_definitions(remill PUBLIC
      "DEBUG"
    )
  else()
    target_compile_options(remill PUBLIC
      -O2
    )
    target_compile_definitions(remill PUBLIC
      "NDEBUG"
    )
  endif()
endif()

target_compile_definitions(remill PUBLIC
  "REMILL_INSTALL_SEMANTICS_DIR=\"${REMILL_INSTALL_SEMANTICS_DIR}/\""
  "REMILL_BUILD_SEMANTICS_DIR_X86=\"${REMILL_BUILD_SEMANTICS_DIR_X86}\""
  "REMILL_BUILD_SEMANTICS_DIR_AARCH64=\"${REMILL_BUILD_SEMANTICS_DIR_AARCH64}\""
)

#
# Also install clang, libllvm and llvm-link
#

function(InstallExternalTarget target_name target_path install_directory installed_file_name)
  # Get the optional rpath parameter
  set(additional_arguments ${ARGN})
  list(LENGTH additional_arguments additional_argument_count)

  if("${additional_argument_count}" EQUAL 0)
  elseif("${additional_argument_count}" EQUAL 1)
    list(GET additional_arguments 0 rpath)
  else()
    message(FATAL_ERROR "InstallExternalTarget: Invalid argument count")
  endif()

  # We need to locate the patchelf executable to fix the rpath; search for it
  # only once, and then export the variable with PARENT_SCOPE so that we can
  # re-use it in the next calls
  if(NOT "${rpath}" STREQUAL "")
    if("${PATCHELF_LOCATION}" STREQUAL "")
      find_program("program_location" "patchelf")
      if("${program_location}" STREQUAL "program_location-NOTFOUND")
        message(FATAL_ERROR "InstallExternalTarget: Failed to locate the patchelf executable")
      endif()

      # We need to set it both in local and in parent scope
      set("PATCHELF_LOCATION" "${program_location}" PARENT_SCOPE)
      set("PATCHELF_LOCATION" "${program_location}")
    endif()
  endif()

  # Make sure the parameters are correct
  if(NOT EXISTS "${target_path}")
    message(FATAL_ERROR "InstallExternalTarget: The following path does not exists: ${target_path}")
  endif()

  if("${target_name}")
    message(FATAL_ERROR "InstallExternalTarget: The following target already exists: ${target_name}")
  endif()

  if("${install_directory}" STREQUAL "")
    message(FATAL_ERROR "InstallExternalTarget: Invalid install directory specified")
  endif()

  # Generate the target
  set("output_file_path" "${CMAKE_CURRENT_BINARY_DIR}/${installed_file_name}")

  if(NOT "${rpath}" STREQUAL "")
    set(CHRPATH_COMMAND ${PATCHELF_LOCATION} --set-rpath ${rpath} ${output_file_path})
  else()
    set(CHRPATH_COMMAND ${CMAKE_COMMAND} -E echo 'No rpath patch needed for ${target_name}')
  endif()

  add_custom_command(
    OUTPUT "${output_file_path}"

    COMMAND "${CMAKE_COMMAND}" -E copy ${target_path} ${output_file_path}
    COMMAND ${CHRPATH_COMMAND}
  )

  add_custom_target("${target_name}" ALL DEPENDS "${output_file_path}")

  install(FILES "${output_file_path}"
    DESTINATION "${install_directory}"
    PERMISSIONS OWNER_READ OWNER_EXECUTE
                GROUP_READ GROUP_EXECUTE
                WORLD_READ WORLD_EXECUTE
  )
endfunction()

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

  InstallExternalTarget("ext_clang" "${clang_location}" "${install_folder}/bin"
    "${INSTALLED_CLANG_NAME}" "${install_folder}/lib")

  InstallExternalTarget("ext_llvmlink" "${llvmlink_location}" "${install_folder}/bin"
    "${INSTALLED_LLVMLINK_NAME}" "${install_folder}/lib")

else()
  # The executable in our binary repository are statically built, meaning that we don't need
  # to change the rpath
  InstallExternalTarget("ext_clang" "${CXX_COMMON_REPOSITORY_ROOT}/llvm/bin/clang${executable_extension}"
    "${install_folder}/bin" "${INSTALLED_CLANG_NAME}")

  InstallExternalTarget("ext_llvmlink" "${CXX_COMMON_REPOSITORY_ROOT}/llvm/bin/llvm-link${executable_extension}"
    "${install_folder}/bin" "${INSTALLED_LLVMLINK_NAME}")
endif()

install(TARGETS "${PROJECT_NAME}"
  ARCHIVE DESTINATION "${install_folder}/lib"
  PUBLIC_HEADER DESTINATION "${install_folder}/include"
)

set(REMILL_LIBRARY_LOCATION "${install_folder}/lib/libremill.a")
set(REMILL_INCLUDE_LOCATION "${install_folder}/include")
get_target_property(REMILL_COMPILE_OPTIONS remill COMPILE_OPTIONS)
get_target_property(REMILL_COMPILE_DEFINITIONS remill COMPILE_DEFINITIONS)

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
if(NOT "x{$LINKER_START_GROUP}x" STREQUAL "xx")
  list(INSERT THIRDPARTY_LIBRARY_FILES 0 "${LINKER_START_GROUP}")
  list(APPEND THIRDPARTY_LIBRARY_FILES "${LINKER_END_GROUP}")
endif()

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
  DESTINATION "${install_folder}/lib/cmake/remill"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Arch.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Instruction.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Name.h"

  DESTINATION "${install_folder}/include/remill/Arch"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/ABI.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Annotate.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/DeadStoreEliminator.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/IntrinsicTable.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Lifter.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Optimizer.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Util.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Version.h"

  DESTINATION "${install_folder}/include/remill/BC"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/Attributes.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/BitcodeReaderWriter.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/CallingConvention.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/CTypes.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/DataLayout.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/DebugInfo.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/Error.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/FileSystem.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/GlobalValue.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/IRReader.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/JITSymbol.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/RuntimeDyld.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/ScalarTransforms.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/TargetLibraryInfo.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/ToolOutputFile.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/Verifier.h"

  DESTINATION "${install_folder}/include/remill/BC/Compat"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/OS/OS.h"
  DESTINATION "${install_folder}/include/remill/OS"
)

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/Definitions.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/HyperCall.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/Intrinsics.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/Operators.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/Runtime.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/State.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Runtime/Types.h"

  DESTINATION "${install_folder}/include/remill/Arch/Runtime"
)

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/X86/Runtime/State.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/X86/Runtime/Types.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/X86/Runtime/Operators.h"

  DESTINATION "${install_folder}/include/remill/Arch/X86/Runtime"
)

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/AArch64/Runtime/State.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/AArch64/Runtime/Types.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/AArch64/Runtime/Operators.h"

  DESTINATION "${install_folder}/include/remill/Arch/AArch64/Runtime"
)

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Version/Version.h"
  DESTINATION "${install_folder}/include/remill/Version"
)

#
# additional targets
#

add_custom_target(semantics)

# runtimes
add_subdirectory(remill/Arch/X86/Runtime)
add_subdirectory(remill/Arch/AArch64/Runtime)

# tools
add_subdirectory(tools)

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
