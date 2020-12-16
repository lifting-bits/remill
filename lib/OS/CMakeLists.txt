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

add_library(remill_os STATIC
  "${REMILL_INCLUDE_DIR}/remill/OS/FileSystem.h"
  "${REMILL_INCLUDE_DIR}/remill/OS/OS.h"

  Compat.cpp
  FileSystem.cpp
  OS.cpp
)

set_property(TARGET remill_os PROPERTY POSITION_INDEPENDENT_CODE ON)

target_link_libraries(remill_os LINK_PRIVATE
  remill_settings
)

install(
  TARGETS remill_os
  EXPORT remillTargets
)
