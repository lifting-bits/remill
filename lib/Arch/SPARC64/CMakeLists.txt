# Copyright (c) 2020 Trail of Bits, Inc.
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

add_library(remill_arch_sparc64 STATIC
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Definitions.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/HyperCall.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Intrinsics.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Operators.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Runtime.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/State.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/Runtime/Types.h"

  "${REMILL_INCLUDE_DIR}/remill/Arch/SPARC64/Runtime/State.h"
  "${REMILL_INCLUDE_DIR}/remill/Arch/SPARC64/Runtime/Types.h"

  "${REMILL_LIB_DIR}/Arch/SPARC32/Decode.h"

  Arch.cpp
  Decode.h
  Extract.cpp
)

set_property(TARGET remill_arch_sparc64 PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_arch_sparc64 LINK_PUBLIC
  remill_settings
)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS remill_arch_sparc64
    EXPORT remillTargets
  )
endif()
