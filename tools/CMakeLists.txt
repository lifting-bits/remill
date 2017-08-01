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

#
# compiler selection
#

if (DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX})
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

#
# compiler settings
#

# enable the gnu extensions
set(CMAKE_CXX_EXTENSIONS ON)

# visual studio already defaults to c++11
if (NOT WIN32)
    set(CMAKE_CXX_STANDARD 11)
endif ()


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

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
    set(LIBRARY_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES})
    include("${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake")

    message(STATUS "Using the following library repository: ${LIBRARY_REPOSITORY_ROOT}")
else ()
    message(STATUS "Using system libraries")
endif ()

# -----------------------------------------------------------------------------

# mcsema needs to be manually cloned into this repo.
if (EXISTS ${CMAKE_SOURCE_DIR}/tools/mcsema)
    add_subdirectory(mcsema)
endif ()

if (EXISTS ${CMAKE_SOURCE_DIR}/tools/vmill)
#    add_subdirectory(vmill)
endif ()
