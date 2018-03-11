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

# Fix behavior of CMAKE_CXX_STANDARD when targeting macOS.
if (POLICY CMP0025)
  cmake_policy(SET CMP0025 NEW)
endif ()

project(remill)
cmake_minimum_required(VERSION 3.2)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/BCCompiler.cmake")
include(CTest)

FindAndSelectClangCompiler()

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

find_package(LLVM REQUIRED CONFIG HINTS ${FINDPACKAGE_LLVM_HINTS})

string(REPLACE "." ";" LLVM_VERSION_LIST ${LLVM_PACKAGE_VERSION})
list(GET LLVM_VERSION_LIST 0 LLVM_MAJOR_VERSION)
list(GET LLVM_VERSION_LIST 1 LLVM_MINOR_VERSION)

set(LLVM_LIBRARIES
  LLVMCore LLVMSupport LLVMAnalysis LLVMipo LLVMIRReader
  LLVMBitReader LLVMBitWriter LLVMTransformUtils LLVMScalarOpts
  LLVMLTO
)

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

# windows sdk
if(DEFINED WIN32)
  list(APPEND PROJECT_LIBRARIES "Kernel32.lib")
endif()

#
# target settings
#

if(DEFINED WIN32)
  list(APPEND PROJECT_DEFINITIONS "REMILL_INSTALL_SEMANTICS_DIR=\"${install_folder}/${REMILL_LLVM_VERSION}/semantics/\"")
else()
  list(APPEND PROJECT_DEFINITIONS "REMILL_INSTALL_SEMANTICS_DIR=\"${CMAKE_INSTALL_PREFIX}/share/remill/${REMILL_LLVM_VERSION}/semantics/\"")
endif()

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

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since sub-tools of remill include remill's headers directly.
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS} ${GLOBAL_DEFINITIONS})
target_compile_options(${PROJECT_NAME} PUBLIC ${GLOBAL_CXXFLAGS})

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

set(REMILL_LLVM_VERSION "${LLVM_MAJOR_VERSION}.${LLVM_MINOR_VERSION}")
math(EXPR REMILL_LLVM_VERSION_NUMBER "${LLVM_MAJOR_VERSION} * 100 + ${LLVM_MINOR_VERSION}")

set(INSTALLED_CLANG_NAME "remill-clang-${REMILL_LLVM_VERSION}${executable_extension}")
set(INSTALLED_LLVMLINK_NAME "remill-llvm-link-${REMILL_LLVM_VERSION}${executable_extension}")

if("${LIBRARY_REPOSITORY_ROOT}" STREQUAL "" OR NOT EXISTS "${LIBRARY_REPOSITORY_ROOT}/llvm")
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
  InstallExternalTarget("ext_clang" "${LIBRARY_REPOSITORY_ROOT}/llvm/bin/clang${executable_extension}"
    "${install_folder}/bin" "${INSTALLED_CLANG_NAME}")

  InstallExternalTarget("ext_llvmlink" "${LIBRARY_REPOSITORY_ROOT}/llvm/bin/llvm-link${executable_extension}"
    "${install_folder}/bin" "${INSTALLED_LLVMLINK_NAME}")
endif()

install(TARGETS "${PROJECT_NAME}"
  ARCHIVE DESTINATION "${install_folder}/lib"
  PUBLIC_HEADER DESTINATION "${install_folder}/include"
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/cmake/remillConfig.cmake"
  DESTINATION "${install_folder}/lib"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Arch.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Instruction.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/Arch/Name.h"

  DESTINATION "${install_folder}/include/remill/Arch"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/ABI.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/IntrinsicTable.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Lifter.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Util.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Version.h"

  DESTINATION "${install_folder}/include/remill/BC"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/CallingConvention.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/GlobalValue.h"
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/BC/Compat/TargetLibraryInfo.h"

  DESTINATION "${install_folder}/include/remill/BC/Compat"
)

install(FILES 
  "${CMAKE_CURRENT_SOURCE_DIR}/remill/OS/OS.h"
  DESTINATION "${install_folder}/include/remill/OS"
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

if(NOT "${PLATFORM_NAME}" STREQUAL "windows")
  if(${IS_AMD64_MACHINE})
    # only enable x86 tests when compiling under x64
    if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
      add_subdirectory(tests/X86)
    endif()

    # only enable aarch64 tests when compiling under aarch64.
    if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64")
      add_subdirectory(tests/AArch64)
    endif()
  endif()
endif()
