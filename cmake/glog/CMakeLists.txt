project(Glog)
cmake_minimum_required(VERSION 2.6)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR})
include(CheckIncludeFiles)
include(GlogDownloader)

check_include_files("pthread.h" HAVE_PTHREAD)

if(CMAKE_COMPILER_IS_GNUCXX OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  include(CheckIncludeFileCXX)
  set(CMAKE_REQUIRED_FLAGS "-std=c++11")
  set(CMAKE_REQUIRED_FLAGS )
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(GLOG_ROOT "" CACHE PATH "Location of GLog sources.")
option(DOWNLOAD_GLOG "Download GLog sources." ON)

if (NOT GLOG_ROOT AND DOWNLOAD_GLOG)
  glog_download_and_extract("0.3.4" GLOG_SOURCE_PATH)
  if(GLOG_SOURCE_PATH)
    set(GLOG_ROOT "${GLOG_SOURCE_PATH}" CACHE
      PATH "Location of GLog sources." FORCE)
  endif()
endif()

if(NOT GLOG_ROOT)
  message(FATAL_ERROR "GLOG_ROOT must be set to the location of glog sources.")
else()
  message(STATUS "GLog sources in ${GLOG_ROOT}")
endif()

add_subdirectory("${GLOG_ROOT}")

