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

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES}
        CACHE PATH "Location of cxx-common libraries.")
endif ()

if (DEFINED LIBRARY_REPOSITORY_ROOT)
    set(TOB_CMAKE_INCLUDE "${LIBRARY_REPOSITORY_ROOT}/cmake_modules/repository.cmake")
    set(LEGACY_TOB_CMAKE_INCLUDE "${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    if (EXISTS "${LEGACY_TOB_CMAKE_INCLUDE}")
        include("${LEGACY_TOB_CMAKE_INCLUDE}")
        message(WARNING "Using legacy cxx-common build; please update!")
    elseif (EXISTS "${TOB_CMAKE_INCLUDE}")
        include("${TOB_CMAKE_INCLUDE}")

    else ()
        message(FATAL_ERROR "The library repository could not be found!")
    endif ()

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

#
# compiler selection
#

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
        set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang"
            CACHE PATH "Path to clang binary.")
    else ()
        set(CMAKE_C_COMPILER "clang")
    endif ()
endif ()

if (NOT DEFINED CMAKE_CXX_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++"
            CACHE PATH "Path to clang++ binary.")
    else ()
        set(CMAKE_CXX_COMPILER "clang++")
    endif ()
endif ()

if (NOT DEFINED CMAKE_ASM_COMPILER)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++"
            CACHE PATH "Path to assembler (aka clang) binary.")
    else ()
        set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})
    endif ()
endif ()

if (NOT DEFINED CMAKE_LLVM_LINK)
    if (DEFINED LLVM_INSTALL_PREFIX)
        set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link"
            CACHE PATH "Path to llvm-link binary.")
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
math(EXPR REMILL_LLVM_VERSION_NUMBER "${LLVM_MAJOR_VERSION} * 100 + ${LLVM_MINOR_VERSION}" )

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

set_property(TARGET ${PROJECT_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since sub-tools of remill include remill's headers directly.
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

# add everything as public.
target_link_libraries(${PROJECT_NAME} PUBLIC ${PROJECT_LIBRARIES})
target_include_directories(${PROJECT_NAME} PUBLIC SYSTEM ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${PROJECT_NAME} PUBLIC ${PROJECT_DEFINITIONS})
set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS ${PROJECT_CXXFLAGS})

#
# Also install clang, libllvm and llvm-link
#

function (InstallExternalTarget target_name target_path install_directory installed_file_name)
  # Get the optional rpath parameter
  set(additional_arguments ${ARGN})
  list(LENGTH additional_arguments additional_argument_count)

  if ("${additional_argument_count}" EQUAL 0)
  elseif ("${additional_argument_count}" EQUAL 1)
    list(GET additional_arguments 0 rpath)
  else ()
    message(FATAL_ERROR "InstallExternalTarget: Invalid argument count")
  endif ()

  # We need to locate the patchelf executable to fix the rpath; search for it
  # only once, and then export the variable with PARENT_SCOPE so that we can
  # re-use it in the next calls
  if (NOT "${rpath}" STREQUAL "")
    if ("${PATCHELF_LOCATION}" STREQUAL "")
      find_program("program_location" "patchelf")
      if ("${program_location}" STREQUAL "program_location-NOTFOUND")
        message(FATAL_ERROR "InstallExternalTarget: Failed to locate the patchelf executable")
      endif ()

      # We need to set it both in local and in parent scope
      set("PATCHELF_LOCATION" "${program_location}" PARENT_SCOPE)
      set("PATCHELF_LOCATION" "${program_location}")
    endif ()
  endif ()

  # Make sure the parameters are correct
  if (NOT EXISTS "${target_path}")
    message(FATAL_ERROR "InstallExternalTarget: The following path does not exists: ${target_path}")
  endif ()

  if ("${target_name}")
    message(FATAL_ERROR "InstallExternalTarget: The following target already exists: ${target_name}")
  endif ()

  if ("${install_directory}" STREQUAL "")
    message(FATAL_ERROR "InstallExternalTarget: Invalid install directory specified")
  endif ()

  # Generate the target
  set("output_file_path" "${CMAKE_CURRENT_BINARY_DIR}/${installed_file_name}")

  if (NOT "${rpath}" STREQUAL "")
    set(CHRPATH_COMMAND ${PATCHELF_LOCATION} --set-rpath ${rpath} ${output_file_path})
  else ()
    set(CHRPATH_COMMAND ${CMAKE_COMMAND} -E echo 'No rpath patch needed for ${target_name}')
  endif ()

  add_custom_command(
    OUTPUT "${output_file_path}"

    COMMAND "${CMAKE_COMMAND}" -E copy ${target_path} ${output_file_path}
    COMMAND ${CHRPATH_COMMAND}
  )

  add_custom_target("${target_name}" ALL DEPENDS "${output_file_path}")
  install(FILES "${output_file_path}" DESTINATION "${install_directory}")
endfunction ()

set(INSTALLED_CLANG_NAME "remill-clang-${REMILL_LLVM_VERSION}")
set(INSTALLED_LLVMLINK_NAME "remill-llvm-link-${REMILL_LLVM_VERSION}")

if ("${LIBRARY_REPOSITORY_ROOT}" STREQUAL "")
  set(INSTALLED_LIBLLVM_NAME "libLLVM-${REMILL_LLVM_VERSION}.so")

  # system binaries are not built statically, so we need to fix the rpath
  find_program("clang_location" "clang-${REMILL_LLVM_VERSION}")
  if ("${clang_location}" STREQUAL "clang_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the clang executable")
  endif ()

  message("InstallExternalTarget: Found clang executable: ${clang_location}")

  find_program("llvmlink_location" "llvm-link")
  if ("${llvmlink_location}" STREQUAL "llvmlink_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the llvm-link executable")
  endif ()

  message("InstallExternalTarget: Found llvm-link executable: ${llvmlink_location}")

  find_library("libllvm_location" "libLLVM-${REMILL_LLVM_VERSION}.so")
  if ("${libllvm_location}" STREQUAL "libllvm_location-NOTFOUND")
    message(FATAL_ERROR "InstallExternalTarget: Failed to locate the libLLVM dynamic library")
  endif ()
  
  message("InstallExternalTarget: Found libLLVM location: ${libllvm_location}")

  InstallExternalTarget("ext_clang" "${clang_location}" "${CMAKE_INSTALL_PREFIX}/bin"
    "${INSTALLED_CLANG_NAME}" "${CMAKE_INSTALL_PREFIX}/lib")

  InstallExternalTarget("ext_llvmlink" "${llvmlink_location}" "${CMAKE_INSTALL_PREFIX}/bin"
    "${INSTALLED_LLVMLINK_NAME}" "${CMAKE_INSTALL_PREFIX}/lib")

  InstallExternalTarget("ext_libllvm" "${libllvm_location}" "${CMAKE_INSTALL_PREFIX}/lib"
    "${INSTALLED_LIBLLVM_NAME}")

else ()
  # The executable in our binary repository are statically built, meaning that we don't need
  # to change the rpath
  InstallExternalTarget("ext_clang" "${LIBRARY_REPOSITORY_ROOT}/llvm/bin/clang-${REMILL_LLVM_VERSION}"
    "${CMAKE_INSTALL_PREFIX}/bin" "${INSTALLED_CLANG_NAME}")

  InstallExternalTarget("ext_llvmlink" "${LIBRARY_REPOSITORY_ROOT}/llvm/bin/llvm-link"
    "${CMAKE_INSTALL_PREFIX}/bin" "${INSTALLED_LLVMLINK_NAME}")
endif ()

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
