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

cmake_minimum_required (VERSION 3.2)
project(arm_runtime)

set(ARMRUNTIME_SOURCEFILES
  Instructions.cpp
  BasicBlock.cpp
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

function (add_runtime_helper target_name address_bit_size little_endian)
  message(" > Generating runtime target: ${target_name}")

  add_runtime(${target_name}
    SOURCES ${ARMRUNTIME_SOURCEFILES}
    ADDRESS_SIZE ${address_bit_size}
    DEFINITIONS "LITTLE_ENDIAN=${little_endian}"
    BCFLAGS -std=c++11
    INCLUDEDIRECTORIES "${CMAKE_SOURCE_DIR}"
    INSTALLDESTINATION "share/remill/${REMILL_LLVM_VERSION}/semantics"

    DEPENDENCIES
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/CONVERT.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/BITBYTE.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/SIMD.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/COND.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/BINARY.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/SHIFT.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/BRANCH.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/DATAXFER.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/CALL_RET.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/MISC.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/FLAGS.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/LOGICAL.cpp"
    "${CMAKE_SOURCE_DIR}/remill/Arch/AArch64/Semantics/SYSTEM.cpp"    
  )
endfunction()

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    #add_runtime_helper(aarch64be 64 0)
    add_runtime_helper(aarch64 64 1)
endif ()
