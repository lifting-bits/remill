# Copyright (c) 2022-present Trail of Bits, Inc.
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
project(ppc_runtime)

set(PPCRUNTIME_SOURCEFILES
  Instructions.cpp

  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")

# Visual C++ requires C++14
if(WIN32)
  set(required_cpp_standard "c++17")
else()
  set(required_cpp_standard "c++17")
endif()

add_runtime(ppc
  SOURCES ${PPCRUNTIME_SOURCEFILES}
  ADDRESS_SIZE 32
  DEFINITIONS "LITTLE_ENDIAN=${little_endian}"
  BCFLAGS "-std=${required_cpp_standard}"
  INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
  INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
  ARCH ppc

  DEPENDENCIES
  "${REMILL_INCLUDE_DIR}/remill/Arch/PPC/Runtime/State.h"
)
