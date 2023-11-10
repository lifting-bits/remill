
include(CMakeDependentOption)

set(can_enable_testing FALSE)
set(can_enable_testing_x86 FALSE)
set(can_enable_testing_aarch64 FALSE)

# tests
if("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
  if(NOT "${PLATFORM_NAME}" STREQUAL "windows")
    if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "AMD64" OR "${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
      set(can_enable_testing_x86 TRUE)
    endif()
  endif()

  if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "aarch64" AND "${PLATFORM_NAME}" STREQUAL "linux")
    message(STATUS "aarch64 tests enabled")
    set(can_enable_testing_aarch64 TRUE)
  endif()
endif()

set(REMILL_SOURCE_DIR "${PROJECT_SOURCE_DIR}" CACHE PATH "Root directory of remill source code")
set(REMILL_INSTALL_LIB_DIR "${CMAKE_INSTALL_LIBDIR}" CACHE PATH "Directory in which remill libraries will be installed")
set(REMILL_INSTALL_BIN_DIR "${CMAKE_INSTALL_BINDIR}" CACHE PATH "Directory in which remill binaries will be installed")
set(REMILL_INSTALL_INCLUDE_DIR "${CMAKE_INSTALL_INCLUDEDIR}" CACHE PATH "Directory in which remill headers will be installed")
set(REMILL_INSTALL_SHARE_DIR "${CMAKE_INSTALL_DATADIR}" CACHE PATH "Directory in which remill cmake files will be installed")
option(REMILL_ENABLE_INSTALL_TARGET "Should Remill be installed?" TRUE)
cmake_dependent_option(REMILL_ENABLE_TESTING "Build your tests" ON "can_enable_testing" OFF)
cmake_dependent_option(REMILL_ENABLE_TESTING_X86 "Build your tests" ON "REMILL_ENABLE_TESTING;can_enable_testing_x86" OFF)
cmake_dependent_option(REMILL_ENABLE_TESTING_AARCH64 "Build your tests" ON "REMILL_ENABLE_TESTING;can_enable_testing_aarch64" OFF)
cmake_dependent_option(REMILL_ENABLE_TESTING_SLEIGH_THUMB "Build cross platform sleigh tests thumb" ON "REMILL_ENABLE_TESTING" OFF)
cmake_dependent_option(REMILL_ENABLE_TESTING_SLEIGH_PPC "Build cross platform sliegh tests for ppc" ON "REMILL_ENABLE_TESTING" OFF)
cmake_dependent_option(REMILL_ENABLE_DIFFERENTIAL_TESTING "Build cross platform differential testing of sleigh x86" ON "REMILL_ENABLE_TESTING" OFF)
