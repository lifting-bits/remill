#add_library(differential-runtime  SHARED Runtime.cpp)

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
)

set_property(TARGET lift-and-compare   PROPERTY POSITION_INDEPENDENT_CODE ON)

