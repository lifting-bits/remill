add_library(
  test-runner
  LiftAndCompare.cpp
  Whitelist.cpp
  Whitelist.h
)

target_link_libraries(
  test-runner
  PRIVATE
  remill
  thirdparty_glog
)

set_property(TARGET test-runner PROPERTY POSITION_INDEPENDENT_CODE ON)
