# Copyright (c) 2026 Trail of Bits, Inc.
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

enable_testing()

# One executable per architecture: both define the global `State` type.
foreach(arch IN ITEMS sparc32 sparc64)
  string(TOUPPER "${arch}" arch_upper)
  add_executable(run-${arch}-tests ${arch_upper}Test.cpp SPARCTestRunner.h)
  add_test(NAME "${arch}-tests" COMMAND "run-${arch}-tests")
  target_link_libraries(run-${arch}-tests
    PRIVATE
    GTest::gtest
    remill
    test-runner
    glog::glog
  )
  set_property(TARGET run-${arch}-tests PROPERTY ENABLE_EXPORTS ON)
endforeach()
