# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.6)
project(arm_runtime)

set(ARMRUNTIME_SOURCEFILES
  Instructions.cpp
  BasicBlock.cpp

  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

function(add_runtime_helper target_name little_endian)
  message(" > Generating runtime target: ${target_name}")

  # Visual C++ requires C++14
  if(WIN32)
    set(required_cpp_standard "c++17")
  else()
    set(required_cpp_standard "c++17")
  endif()

  # necessary to build code as 32-bit
  # on aarch64
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64.*|AARCH64.*|arm64.*|ARM64.*)" AND "${PLATFORM_NAME}" STREQUAL "linux")
    set(arch_flags "--target=arm-linux-gnueabihf")
  else()
    set(arch_flags "-m32")
  endif()

  add_runtime(${target_name}
    SOURCES ${ARMRUNTIME_SOURCEFILES}
    ADDRESS_SIZE 32
    DEFINITIONS "LITTLE_ENDIAN=${little_endian}"
    BCFLAGS "${arch_flags}" "-std=${required_cpp_standard}"
    INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
    INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
    ARCH arm
  )
endfunction()

add_runtime_helper(aarch32 1)
add_runtime_helper(thumb2 1)
