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

cmake_minimum_required (VERSION 3.2)
project(x86_runtime BC)

set(X86RUNTIME_SOURCEFILES
    Instructions.cpp
    BasicBlock.cpp
)

set_source_files_properties(Instructions.cpp PROPERTIES COMPILE_FLAGS "-O3 -g0")
set_source_files_properties(BasicBlock.cpp PROPERTIES COMPILE_FLAGS "-O0 -g3")

set(X86RUNTIME_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

function (add_runtime_helper target_name address_bit_size enable_avx enable_avx512)
    message(" > Generating runtime target: ${target_name}")

    add_runtime(${target_name} SOURCES ${X86RUNTIME_SOURCEFILES} ADDRESS_SIZE ${address_bit_size})

    target_include_directories(${target_name} PRIVATE ${X86RUNTIME_INCLUDEDIRECTORIES})
    target_compile_definitions(${target_name} PRIVATE "HAS_FEATURE_AVX=${enable_avx}")
    target_compile_definitions(${target_name} PRIVATE "HAS_FEATURE_AVX512=${enable_avx512}")

    install(TARGETS ${target_name} DESTINATION "share/remill/${REMILL_LLVM_VERSION}/semantics")

endfunction ()

add_runtime_helper(x86 32 0 0)
add_runtime_helper(x86_avx 32 1 0)
add_runtime_helper(x86_avx512 32 1 1)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_runtime_helper(amd64 64 0 0)
    add_runtime_helper(amd64_avx 64 1 0)
    add_runtime_helper(amd64_avx512 64 1 1)
endif ()
