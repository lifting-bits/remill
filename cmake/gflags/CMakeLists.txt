project(Gflags)
cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include(CheckIncludeFiles)
include(GflagsDownloader)

check_include_files("pthread.h" HAVE_PTHREAD)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  include(CheckIncludeFileCXX)
  set(CMAKE_REQUIRED_FLAGS "-std=c++11")
  set(CMAKE_REQUIRED_FLAGS )
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(GFLAGS_ROOT "" CACHE PATH "Location of gflags sources.")
option(DOWNLOAD_GFLAGS "Download GFlags sources." ON)

if (NOT GFLAGS_ROOT AND DOWNLOAD_GFLAGS)
  gflags_download_and_extract("2.2.0" GFLAGS_SOURCE_PATH)
  if(GFLAGS_SOURCE_PATH)
    set(GFLAGS_ROOT "${GFLAGS_SOURCE_PATH}" CACHE
      PATH "Location of GFlags sources." FORCE)
  endif()
endif()

if(NOT GFLAGS_ROOT)
  message(FATAL_ERROR "GFLAGS_ROOT must be set to the location of gflags sources.")
else()
  message(STATUS "GFlags sources in ${GFLAGS_ROOT}")
endif()

add_subdirectory("${GFLAGS_ROOT}")

