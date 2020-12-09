if (DEFINED ENV{TRAILOFBITS_LIBRARIES})
  message(STATUS "Using old build system")
  # Fix behavior of CMAKE_CXX_STANDARD when targeting macOS.
  if (POLICY CMP0025)
    cmake_policy(SET CMP0025 NEW)
  endif ()

  project(remill)
  cmake_minimum_required(VERSION 3.2)
  include(CMakeLists_old.txt)
else()
  message(STATUS "Using new vcpkg build system")
  include(cmake/vcpkg_helper.cmake)

  project(remill)
  cmake_minimum_required(VERSION 3.14)
  include(CMakeLists_vcpkg.txt)
endif()
