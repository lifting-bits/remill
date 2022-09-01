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

find_package(Python COMPONENTS Interpreter)
add_executable(
  lift-and-compare
  LiftAndCompare.cpp
  Whitelist.cpp
  Whitelist.h
)

target_link_libraries(
  lift-and-compare
  PRIVATE
  remill
  glog::glog
  test-runner
)

set_property(TARGET lift-and-compare PROPERTY ENABLE_EXPORTS ON)
set_property(TARGET lift-and-compare PROPERTY POSITION_INDEPENDENT_CODE ON)
enable_testing()

add_test(NAME "small_diff_test" COMMAND "${Python_EXECUTABLE}" ${REMILL_SOURCE_DIR}/scripts/diff_tester_export_insns/diff_tester_export_insns/ci_runner.py --required_success_rate 1.0 --difftester_bin ${CMAKE_BINARY_DIR}/bin/differential_tester_x86/lift-and-compare --workdir ${CMAKE_BINARY_DIR} ${REMILL_SOURCE_DIR}/bin/differential_tester_x86/data/small_test/ --whitelist_file ${REMILL_SOURCE_DIR}/bin/differential_tester_x86/whitelist.json)
