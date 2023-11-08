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

cmake_minimum_required(VERSION 3.6)
project(x86_runtime)

set(X86RUNTIME_SOURCEFILES
  Instructions.cpp
  BasicBlock.cpp

  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

function(add_runtime_helper target_name address_bit_size enable_avx enable_avx512)
  message(" > Generating runtime target: ${target_name}")

  # Visual C++ requires C++14
  if(WIN32)
    set(required_cpp_standard "c++17")
  else()
    set(required_cpp_standard "c++11")
  endif()

  if (address_bit_size EQUAL 32)
    set(x86_arch "i386")
  else()
    set(x86_arch "x86_64")
  endif()

  add_runtime(${target_name}
    SOURCES ${X86RUNTIME_SOURCEFILES}
    ADDRESS_SIZE ${address_bit_size}
    DEFINITIONS "HAS_FEATURE_AVX=${enable_avx}" "HAS_FEATURE_AVX512=${enable_avx512}"
    BCFLAGS "-std=${required_cpp_standard}"
    INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
    INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
    ARCH ${x86_arch}

    DEPENDENCIES
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Float.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"

    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Operators.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/State.h"
    "${REMILL_INCLUDE_DIR}/remill/Arch/X86/Runtime/Types.h"

    "${REMILL_LIB_DIR}/Arch/X86/Semantics/CONVERT.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/POP.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/BITBYTE.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/PREFETCH.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/XSAVE.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/MMX.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/SEMAPHORE.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/SYSCALL.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/FMA.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/SSE.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/BINARY.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/SHIFT.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/PUSH.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/AVX.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/DATAXFER.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/XOP.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/STRINGOP.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/ROTATE.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/CMOV.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/FLAGOP.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/UNCOND_BR.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/NOP.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/RTM.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/DECIMAL.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/CALL_RET.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/MISC.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/FLAGS.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/LOGICAL.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/SYSTEM.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/X87.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/COND_BR.cpp"
    "${REMILL_LIB_DIR}/Arch/X86/Semantics/INTERRUPT.cpp"
  )
endfunction()

add_runtime_helper(x86 32 0 0)
add_runtime_helper(x86_avx 32 1 0)
add_runtime_helper(x86_avx512 32 1 1)
add_runtime_helper(x86_sleigh 32 1 1)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_runtime_helper(amd64 64 0 0)
  add_runtime_helper(amd64_sleigh 64 0 0)
  add_runtime_helper(amd64_avx 64 1 0)
  add_runtime_helper(amd64_avx512 64 1 1)
endif()
