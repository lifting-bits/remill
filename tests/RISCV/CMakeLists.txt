# Copyright (c) 2026-present Trail of Bits, Inc.
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

add_executable(run-riscv32-tests
  TestLifting32.cpp
  RV32I.cpp
  RV32M.cpp
  RV32A.cpp
  RV32C.cpp
  RV32F.cpp
  RV32D.cpp
  RV32Zicsr.cpp
)

add_test(NAME "riscv32-tests" COMMAND "run-riscv32-tests")
target_link_libraries(
  run-riscv32-tests
  PRIVATE
  GTest::gtest
  remill
  test-runner
  glog::glog
)
set_property(TARGET run-riscv32-tests PROPERTY ENABLE_EXPORTS ON)

add_executable(run-riscv64-tests
  TestLifting64.cpp
  RV64I.cpp
  RV64M.cpp
  RV64A.cpp
  RV64C.cpp
  RV64F.cpp
  RV64D.cpp
  RV64Zicsr.cpp
)

add_test(NAME "riscv64-tests" COMMAND "run-riscv64-tests")
target_link_libraries(
  run-riscv64-tests
  PRIVATE
  GTest::gtest
  remill
  test-runner
  glog::glog
)
set_property(TARGET run-riscv64-tests PROPERTY ENABLE_EXPORTS ON)
