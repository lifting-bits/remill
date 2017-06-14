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

if (NOT DEFINED CMAKE_BC_COMPILER)
    if (NOT "$ENV{LLVM_INSTALL_PREFIX}" STREQUAL "")
        message(STATUS "Setting LLVM_INSTALL_PREFIX from the environment variable...")
        set(LLVM_INSTALL_PREFIX $ENV{TRAILOFBITS_LIBRARIES})
    endif ()

    if (NOT "${LLVM_INSTALL_PREFIX}" STREQUAL "")
        message(STATUS "Using LLVM_INSTALL_PREFIX to locate the bitcode compiler")

        if (NOT EXISTS "${LLVM_INSTALL_PREFIX}/bin/clang++")
            message(SEND_ERROR "Could not find the bitcode compiler set in environment variable LLVM_INSTALL_PREFIX: $ENV{LLVM_INSTALL_PREFIX}.")
        endif ()

        if (NOT EXISTS "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
            message(SEND_ERROR "Could not find the bitcode linker set in environment variable LLVM_INSTALL_PREFIX: $ENV{LLVM_INSTALL_PREFIX}.")
        endif ()

        set(CMAKE_BC_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++" CACHE PATH "Bitcode Compiler")
        set(CMAKE_BC_LINKER "${LLVM_INSTALL_PREFIX}/bin/llvm-link" CACHE PATH "Bitcode Linker")
        set(CMAKE_BC_COMPILER_ENV_VAR "BC_COMPILER")
    else ()
        find_program(CLANG_PATH
            NAMES "clang++"
            PATHS "/usr/bin" "/usr/local/bin"
        )

        find_program(LLVMLINK_PATH
            NAMES "llvm-link"
            PATHS "/usr/bin" "/usr/local/bin"
        )

        if (NOT DEFINED CLANG_PATH OR NOT DEFINED LLVMLINK_PATH)
            message(SEND_ERROR "Could not find the bitcode compiler and linker. Either install Clang in the default or define the LLVM_INSTALL_PREFIX environment variable.")
        endif ()

        set(CMAKE_BC_COMPILER "${CLANG_PATH}" CACHE PATH "Bitcode Compiler")
        set(CMAKE_BC_LINKER "${LLVMLINK_PATH}" CACHE PATH "Bitcode Linker")
        set(CMAKE_BC_COMPILER_ENV_VAR "BC_COMPILER")
    endif ()
endif ()

mark_as_advanced(CMAKE_BC_COMPILER)
mark_as_advanced(CMAKE_BC_LINKER)
mark_as_advanced(CMAKE_BC_COMPILER_ENV_VAR)

if (NOT "${CMAKE_BC_COMPILER}" STREQUAL "")
    message(STATUS "Found bitcode compiler: ${CMAKE_BC_COMPILER}")
endif ()

if (NOT "${CMAKE_BC_LINKER}" STREQUAL "")
    message(STATUS "Found bitcode linker: ${CMAKE_BC_LINKER}")
endif ()

configure_file(${CMAKE_SOURCE_DIR}/cmake/BCCompiler/CMakeBCCompiler.cmake.in ${CMAKE_PLATFORM_INFO_DIR}/CMakeBCCompiler.cmake @ONLY)
