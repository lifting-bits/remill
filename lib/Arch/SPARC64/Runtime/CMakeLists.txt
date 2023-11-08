# Copyright (c) 2019 Trail of Bits, Inc.
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

cmake_minimum_required(VERSION 3.6)
project(sparc64_runtime)

set(SPARC64RUNTIME_SOURCEFILES
  Instructions.cpp
  BasicBlock.cpp

  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

if (REMILL_BARRIER_AS_NOP)
  set(EXTRA_BC_FLAGS "-DREMILL_BARRIER_AS_NOP")
endif(REMILL_BARRIER_AS_NOP)

function(add_runtime_helper target_name little_endian)
  message(" > Generating runtime target: ${target_name}")

  # Visual C++ requires C++14
  if(WIN32)
    set(required_cpp_standard "c++17")
  else()
    set(required_cpp_standard "c++17")
  endif()

  add_runtime(${target_name}
    SOURCES ${SPARC64RUNTIME_SOURCEFILES}
    ADDRESS_SIZE 64
    DEFINITIONS "LITTLE_ENDIAN=${little_endian}"
    BCFLAGS "-std=${required_cpp_standard}" "${EXTRA_BC_FLAGS}"
    INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
    INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
    ARCH sparc64

    DEPENDENCIES
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Float.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"

    "${REMILL_INCLUDE_DIR}/remill/Arch/SPARC64/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/SPARC64/Runtime/Types.h"

    "${REMILL_LIB_DIR}/Arch/SPARC32/Semantics/FLAGS.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC32/Semantics/COND.cpp"

    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/ADDRESS.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/BINARY.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/BITBYTE.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/BRANCH.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/DATAXFER.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/TRAP.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/FOP.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/LOGICAL.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/MISC.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/VIS.cpp"
    "${REMILL_LIB_DIR}/Arch/SPARC64/Semantics/WRASR.cpp"
  )
endfunction()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_runtime_helper(sparc64 0)
endif()
