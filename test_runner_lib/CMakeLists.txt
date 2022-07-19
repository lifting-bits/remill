set(TEST_RUNNER_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

add_library(
  test-runner
  STATIC
  TestRunner.cpp
  "${TEST_RUNNER_INCLUDE_DIR}/test_runner/TestRunner.h"
)

target_link_libraries(
  test-runner
  PRIVATE
  remill
  thirdparty_glog
)

target_include_directories(test-runner PUBLIC "${TEST_RUNNER_INCLUDE_DIR}")

set_property(TARGET test-runner PROPERTY POSITION_INDEPENDENT_CODE ON)
