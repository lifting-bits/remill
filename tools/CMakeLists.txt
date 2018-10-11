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

# mcsema needs to be manually cloned into this repo.
if(EXISTS ${CMAKE_SOURCE_DIR}/tools/mcsema)
  add_subdirectory(mcsema)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/tools/lift)
  add_subdirectory(lift)
endif()

if(EXISTS ${CMAKE_SOURCE_DIR}/tools/fcd)
  add_subdirectory(fcd)
endif()

if (NOT WIN32)
  if (307 LESS ${REMILL_LLVM_VERSION_NUMBER})
      if (EXISTS ${CMAKE_SOURCE_DIR}/tools/vmill)
          add_subdirectory(vmill)
      endif ()
  endif ()
endif ()

