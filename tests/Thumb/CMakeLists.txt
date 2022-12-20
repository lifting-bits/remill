# Copyright (c) 2022 Trail of Bits, Inc.
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

find_package(GTest CONFIG REQUIRED)
list(APPEND PROJECT_LIBRARIES GTest::gtest)

enable_testing()

add_executable(
  run-thumb-tests
  TestLifting.cpp
)

add_test(NAME "thumb-tests" COMMAND "run-thumb-tests")
target_link_libraries(
  run-thumb-tests
  PRIVATE
  GTest::gtest
  remill
  test-runner
  glog::glog
)

set_property(TARGET run-thumb-tests PROPERTY ENABLE_EXPORTS ON)
set_property(TARGET run-thumb-tests PROPERTY POSITION_INDEPENDENT_CODE ON)
