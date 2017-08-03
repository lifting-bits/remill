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

if (NOT DEFINED CMAKE_LL_COMPILER)
    if (NOT "$ENV{LLVM_INSTALL_PREFIX}" STREQUAL "")
        message(STATUS "Setting LLVM_INSTALL_PREFIX from the environment variable...")
        set(LLVM_INSTALL_PREFIX $ENV{TRAILOFBITS_LIBRARIES})
    endif ()

    if (NOT "${LLVM_INSTALL_PREFIX}" STREQUAL "")
        message(STATUS "Using LLVM_INSTALL_PREFIX to locate the LLVM IR compiler")

        if (NOT EXISTS "${LLVM_INSTALL_PREFIX}/bin/llc")
            message(SEND_ERROR "Could not find the LLVM IR compiler set in environment variable LLVM_INSTALL_PREFIX: $ENV{LLVM_INSTALL_PREFIX}.")
        endif ()

        if (NOT EXISTS "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
            message(SEND_ERROR "Could not find the LLVM IR linker set in environment variable LLVM_INSTALL_PREFIX: $ENV{LLVM_INSTALL_PREFIX}.")
        endif ()

        set(CMAKE_LL_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++" CACHE PATH "LLVM IR Compiler")
        set(CMAKE_LL_LINKER "${LLVM_INSTALL_PREFIX}/bin/llvm-link" CACHE PATH "LLVM IR Linker")
        set(CMAKE_LL_COMPILER_ENV_VAR "BC_COMPILER")
    else ()
        find_program(LLC_PATH
            NAMES "llc"
            PATHS "/usr/bin" "/usr/local/bin"
        )

        find_program(LLVMLINK_PATH
            NAMES "llvm-link"
            PATHS "/usr/bin" "/usr/local/bin"
        )

        if (NOT DEFINED LLC_PATH OR NOT DEFINED LLVMLINK_PATH)
            message(SEND_ERROR "Could not find the LLVM IR compiler and linker. Either install Clang in the default or define the LLVM_INSTALL_PREFIX environment variable.")
        endif ()

        set(CMAKE_LL_COMPILER "${LLC_PATH}" CACHE PATH "LLVM IR Compiler")
        set(CMAKE_LL_LINKER "${LLVMLINK_PATH}" CACHE PATH "LLVM IR Linker")
        set(CMAKE_LL_COMPILER_ENV_VAR "BC_COMPILER")
    endif ()
endif ()

mark_as_advanced(CMAKE_LL_COMPILER)
mark_as_advanced(CMAKE_LL_LINKER)
mark_as_advanced(CMAKE_LL_COMPILER_ENV_VAR)

if (NOT "${CMAKE_LL_COMPILER}" STREQUAL "")
    message(STATUS "Found LLVM IR compiler: ${CMAKE_LL_COMPILER}")
endif ()

if (NOT "${CMAKE_LL_LINKER}" STREQUAL "")
    message(STATUS "Found LLVM IR linker: ${CMAKE_LL_LINKER}")
endif ()

configure_file(${CMAKE_SOURCE_DIR}/cmake/LLCompiler/CMakeLLCompiler.cmake.in ${CMAKE_PLATFORM_INFO_DIR}/CMakeLLCompiler.cmake @ONLY)
