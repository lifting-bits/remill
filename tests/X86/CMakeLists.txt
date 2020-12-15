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

project(x86_tests ASM)
cmake_minimum_required(VERSION 3.2)

function(COMPILE_X86_TESTS name address_size has_avx has_avx512)
  set(X86_TEST_FLAGS
    -I${CMAKE_SOURCE_DIR}
    -DADDRESS_SIZE_BITS=${address_size}
    -DHAS_FEATURE_AVX=${has_avx}
    -DHAS_FEATURE_AVX512=${has_avx512}
    -DGTEST_HAS_RTTI=0
    -DGTEST_HAS_TR1_TUPLE=0
  )
    
  add_executable(lift-${name}-tests
    EXCLUDE_FROM_ALL
    Lift.cpp
    Tests.S
  )
    
  target_compile_options(lift-${name}-tests
    PRIVATE ${X86_TEST_FLAGS} -DIN_TEST_GENERATOR
  )
  
  file(GLOB X86_TEST_FILES
    "${CMAKE_CURRENT_LIST_DIR}/*/*.S"
  )
  
  set_target_properties(lift-${name}-tests PROPERTIES OBJECT_DEPENDS "${X86_TEST_FILES}")

  target_link_libraries(lift-${name}-tests PRIVATE remill GTest::gtest)
  target_compile_definitions(lift-${name}-tests PUBLIC ${PROJECT_DEFINITIONS})

  add_custom_command(
    OUTPUT tests_${name}.bc
    COMMAND lift-${name}-tests --arch ${name} --bc_out tests_${name}.bc
    DEPENDS semantics
  )
    
  add_custom_command(
    OUTPUT tests_${name}.S
    COMMAND ${CMAKE_BC_COMPILER} -Wno-override-module -S -O0 -g0 -c tests_${name}.bc -o tests_${name}.S
    DEPENDS tests_${name}.bc
  )
 
  add_executable(run-${name}-tests EXCLUDE_FROM_ALL Run.cpp Tests.S tests_${name}.S)
  set_target_properties(run-${name}-tests PROPERTIES OBJECT_DEPENDS "${X86_TEST_FILES}")

  target_link_libraries(run-${name}-tests PUBLIC remill GTest::gtest)
  target_compile_definitions(run-${name}-tests PUBLIC ${PROJECT_DEFINITIONS})
    
  target_compile_options(run-${name}-tests
    PRIVATE ${X86_TEST_FLAGS}
  )

  message(STATUS "Adding test: ${name} as run-${name}-tests")
  add_test(NAME "${name}" COMMAND "run-${name}-tests")
  add_dependencies(test_dependencies "run-${name}-tests")
endfunction()

find_package(GTest CONFIG REQUIRED)

enable_testing()

if (NOT APPLE)
  COMPILE_X86_TESTS(x86 32 0 0)
  COMPILE_X86_TESTS(x86_avx 32 1 0)
endif()

COMPILE_X86_TESTS(amd64 64 0 0)
COMPILE_X86_TESTS(amd64_avx 64 1 0)
