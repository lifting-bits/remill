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

set(TEST_RUNNER_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

#add_library(
#  test-runner
#  STATIC
#  TestRunner.cpp
#  "${TEST_RUNNER_INCLUDE_DIR}/test_runner/TestRunner.h"
#  "${TEST_RUNNER_INCLUDE_DIR}/test_runner/TestOutputSpec.h"
#)

#target_link_libraries(
#  test-runner
#  PRIVATE
#  remill
#  glog::glog
#)

#target_include_directories(test-runner PUBLIC "${TEST_RUNNER_INCLUDE_DIR}")

#set_property(TARGET test-runner PROPERTY POSITION_INDEPENDENT_CODE ON)
