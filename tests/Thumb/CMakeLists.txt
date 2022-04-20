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



enable_testing()

add_executable(
  run-thumb-tests
  TestLifting.cpp
)
target_link_libraries(
  run-thumb-tests  
  GTest::gtest
  remill
  thirdparty_glog
)


message(STATUS "Adding test: thumb as run-thumb-tests")
add_test(NAME "thumb" COMMAND "run-thumb-tests")
