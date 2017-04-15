project(Gtest)
cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include(CheckIncludeFiles)
include(GtestDownloader)

check_include_files("pthread.h" HAVE_PTHREAD)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  include(CheckIncludeFileCXX)
  set(CMAKE_REQUIRED_FLAGS "-std=c++11")
  set(CMAKE_REQUIRED_FLAGS )
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(GTEST_ROOT "" CACHE PATH "Location of Gtest sources.")
option(DOWNLOAD_GTEST "Download Gtest sources." ON)

if (NOT GTEST_ROOT AND DOWNLOAD_GTEST)
  googletest_download_and_extract("1.8.0" GTEST_SOURCE_PATH)
  if(GTEST_SOURCE_PATH)
    set(GTEST_ROOT "${GTEST_SOURCE_PATH}" CACHE
      PATH "Location of Gtest sources." FORCE)
  endif()
endif()

if(NOT GTEST_ROOT)
  message(FATAL_ERROR "GTEST_ROOT must be set to the location of glog sources.")
else()
  message(STATUS "Gtest sources in ${GTEST_ROOT}")
endif()

set(BUILD_GMOCK OFF)
set(BUILD_GTEST ON)
add_subdirectory("${GTEST_ROOT}")

