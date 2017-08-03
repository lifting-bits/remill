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

if (NOT CMAKE_LL_COMPILE_OBJECT)
    if (NOT DEFINED CMAKE_LL_COMPILER)
        message(SEND_ERROR "The LLVM IR compiler was not found!")
    endif ()

    set(CMAKE_LL_COMPILE_OBJECT "${CMAKE_LL_COMPILER} <FLAGS> <SOURCE> -o <OBJECT>")
endif ()

if (NOT CMAKE_LL_LINK_EXECUTABLE)
    if (NOT DEFINED CMAKE_LL_LINKER)
        message(SEND_ERROR "The LLVM IR linker was not found!")
    endif ()

    set(CMAKE_LL_LINK_EXECUTABLE "${CMAKE_LL_LINKER} <OBJECTS> -o <TARGET>")
endif ()

if (NOT CMAKE_INCLUDE_FLAG_BC)
    set(CMAKE_INCLUDE_FLAG_BC -I)
endif ()
