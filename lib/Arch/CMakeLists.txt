# Copyright (c) 2020 Trail of Bits, Inc.
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

add_library(remill_arch STATIC
  "${REMILL_INCLUDE_DIR}/remill/Arch/Arch.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Instruction.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Name.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/ArchBase.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Context.h"

  Arch.cpp
  BitManipulation.h
  Instruction.cpp
  Context.cpp
  Name.cpp
)

add_subdirectory(AArch32)
add_subdirectory(AArch64)
add_subdirectory(PPC)
add_subdirectory(MIPS)
add_subdirectory(SPARC32)
add_subdirectory(SPARC64)
add_subdirectory(Sleigh)
add_subdirectory(X86)

set_property(TARGET remill_arch PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_arch LINK_PUBLIC
  remill_arch_aarch64
  remill_arch_sleigh
  remill_arch_sparc32
  remill_arch_sparc64
  remill_arch_x86
  LINK_PRIVATE
  remill_settings
)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(TARGETS remill_arch
    EXPORT remillTargets)
endif()
