# Copyright (c) 2021 Trail of Bits, Inc.
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

cmake_minimum_required(VERSION 3.2)
project(msp430_runtime)

set(MSP430RUNTIME_SOURCEFILES
  Instructions.cpp
  BasicBlock.cpp
  
  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

if (REMILL_BARRIER_AS_NOP)
  set(EXTRA_BC_FLAGS "-DREMILL_BARRIER_AS_NOP")
endif(REMILL_BARRIER_AS_NOP)

function(add_runtime_helper target_name)
  message(" > Generating runtime target: ${target_name}")
  # Visual C++ requires C++14
  if(WIN32)
    set(required_cpp_standard "c++14")
  else()
    set(required_cpp_standard "c++17")
  endif()

  add_runtime(${target_name}
    SOURCES ${MSP430RUNTIME_SOURCEFILES}
    ADDRESS_SIZE 16
    DEFINITIONS "LITTLE_ENDIAN=1" "REMILL_DISABLE_INT128=1"
    BCFLAGS "-m16" "--target=msp430-elf" "-std=${required_cpp_standard}" "${EXTRA_BC_FLAGS}"
    INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
    INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"

    DEPENDENCIES
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Float.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"

    "${REMILL_INCLUDE_DIR}/remill/Arch/MSP430/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/MSP430/Runtime/Types.h"
    
    "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
  )
endfunction()

add_runtime_helper(msp430)
