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

find_package(GTest CONFIG REQUIRED)
list(APPEND PROJECT_LIBRARIES GTest::gtest)

enable_testing()
enable_language(ASM)

add_executable(lift-aarch64-tests
  EXCLUDE_FROM_ALL
  Lift.cpp
  Tests.S
)

set_target_properties(lift-aarch64-tests PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-fPIC -pie"
)

target_compile_options(lift-aarch64-tests
  PRIVATE ${AARCH64_TEST_FLAGS}
  -DIN_TEST_GENERATOR
)


file(GLOB AARCH64_TEST_FILES
  "${CMAKE_CURRENT_LIST_DIR}/*/*.S"
)

set_target_properties(lift-aarch64-tests PROPERTIES OBJECT_DEPENDS "${AARCH64_TEST_FILES}")

target_link_libraries(lift-aarch64-tests PUBLIC remill ${PROJECT_LIBRARIES} )
target_include_directories(lift-aarch64-tests PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(lift-aarch64-tests PRIVATE ${CMAKE_SOURCE_DIR})

add_executable(run-aarch64-tests
  EXCLUDE_FROM_ALL
  Run.cpp
  Tests.S
  tests_aarch64.S
)

set_target_properties(run-aarch64-tests PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  COMPILE_FLAGS "-fPIC -pie"
  OBJECT_DEPENDS "${AARCH64_TEST_FILES}"
)

add_custom_command(
  OUTPUT tests_aarch64.bc
  COMMAND lift-aarch64-tests --arch aarch64 --bc_out tests_aarch64.bc
  DEPENDS lift-aarch64-tests semantics
)

add_custom_command(
  OUTPUT  tests_aarch64.S
  COMMAND ${CMAKE_BC_COMPILER}
          -Wno-override-module
          -S -O1 -g0
          -c tests_aarch64.bc
          -o tests_aarch64.S
  DEPENDS tests_aarch64.bc
)

target_link_libraries(run-aarch64-tests PUBLIC remill ${PROJECT_LIBRARIES})
target_include_directories(run-aarch64-tests PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_include_directories(run-aarch64-tests PRIVATE ${CMAKE_SOURCE_DIR})

target_compile_options(run-aarch64-tests
  PRIVATE #-I${CMAKE_SOURCE_DIR}
          -DADDRESS_SIZE_BITS=64
          -DGTEST_HAS_RTTI=0
          -DGTEST_HAS_TR1_TUPLE=0
)

message(STATUS "Adding test: aarch64 as run-aarch64-tests")
add_test(NAME "aarch64" COMMAND "run-aarch64-tests")
add_dependencies(test_dependencies run-aarch64-tests)
