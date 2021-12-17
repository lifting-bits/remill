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

add_library(remill_bc STATIC
  "${REMILL_INCLUDE_DIR}/remill/BC/ABI.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/Annotate.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/InstructionLifter.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/IntrinsicTable.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/Lifter.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/Optimizer.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/TraceLifter.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/Util.h"
  "${REMILL_INCLUDE_DIR}/remill/BC/Version.h"

  ABI.cpp
  Annotate.cpp
  InstructionLifter.cpp
  InstructionLifter.h
  IntrinsicTable.cpp
  Optimizer.cpp
  TraceLifter.cpp
  Util.cpp
)

set_property(TARGET remill_bc PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_bc LINK_PRIVATE
  remill_settings
)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS remill_bc
    EXPORT remillTargets
  )
endif()