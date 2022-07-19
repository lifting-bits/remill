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
  thirdparty_glog
  test-runner
)

set_property(TARGET lift-and-compare PROPERTY POSITION_INDEPENDENT_CODE ON)

add_test("small_diff_test" COMMAND "${Python_EXECUTABLE}" ${REMILL_SOURCE_DIR}/scripts/diff_tester_export_insns/diff_tester_export_insns/ci_runner.py --required_success_rate 1.0 --difftester_bin ${CMAKE_BINARY_DIR}/bin/differential_tester_x86/lift-and-compare --workdir ${CMAKE_BINARY_DIR} ${REMILL_SOURCE_DIR}/bin/differential_tester_x86/data/small_test/ --whitelist_file ${REMILL_SOURCE_DIR}/differential_tester_x86/whitelist.json)