# Copyright (c) 2026-present Trail of Bits, Inc.
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

cmake_minimum_required(VERSION 3.21)
project(riscv_runtime)

set(RISCV_RUNTIME_SOURCEFILES
  Instructions.cpp
  "${REMILL_LIB_DIR}/Arch/Runtime/Intrinsics.cpp"
)

add_runtime(riscv32
  SOURCES ${RISCV_RUNTIME_SOURCEFILES}
  ADDRESS_SIZE 32
  DEFINITIONS "LITTLE_ENDIAN=1" "REMILL_DISABLE_INT128=1"
  INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
  INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
  ARCH riscv32

  DEPENDENCIES
  "${REMILL_INCLUDE_DIR}/remill/Arch/RISCV/Runtime/State.h"
)

add_runtime(riscv64
  SOURCES ${RISCV_RUNTIME_SOURCEFILES}
  ADDRESS_SIZE 64
  DEFINITIONS "LITTLE_ENDIAN=1"
  INCLUDEDIRECTORIES "${REMILL_INCLUDE_DIR}" "${REMILL_SOURCE_DIR}"
  INSTALLDESTINATION "${REMILL_INSTALL_SEMANTICS_DIR}"
  ARCH riscv64

  DEPENDENCIES
  "${REMILL_INCLUDE_DIR}/remill/Arch/RISCV/Runtime/State.h"
)
