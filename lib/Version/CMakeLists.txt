# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
# 
# Define the two required variables before including
# the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
include("${CMAKE_SOURCE_DIR}/cmake/git_watcher.cmake")

# Create a library out of the compiled post-configure file.
add_library(remill_version STATIC ${POST_CONFIGURE_FILE})
target_include_directories(remill_version PUBLIC "${REMILL_INCLUDE_DIR}")
add_dependencies(remill_version check_git_${PROJECT_NAME})

install(
  TARGETS remill_version
  ARCHIVE DESTINATION "${REMILL_INSTALL_LIB_DIR}"
  PUBLIC_HEADER DESTINATION "${REMILL_INSTALL_INCLUDE_DIR}"
)