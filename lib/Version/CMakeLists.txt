# Based on: https://github.com/andrew-hardin/cmake-git-version-tracking/blob/master/better-example/CMakeLists.txt
# By Andrew Hardin
# Released under the MIT License.
# https://raw.githubusercontent.com/andrew-hardin/cmake-git-version-tracking/master/LICENSE
#
# Define the two required variables before including
# the source code for watching a git repository.
set(PRE_CONFIGURE_FILE "Version.cpp.in")
set(POST_CONFIGURE_FILE "${CMAKE_CURRENT_BINARY_DIR}/Version.cpp")
include( git_watcher )

configure_file(${PRE_CONFIGURE_FILE} ${POST_CONFIGURE_FILE} @ONLY)

set(Version_PUBLIC_H
    "${REMILL_SOURCE_DIR}/include/remill/Version/Version.h"
)
# Create a library out of the compiled post-configure file.
add_library(remill_version STATIC
  ${POST_CONFIGURE_FILE}
  ${Version_PUBLIC_H}
  )
target_link_libraries(remill_version LINK_PRIVATE remill_settings)

if(REMILL_ENABLE_INSTALL_TARGET)
  install(
    TARGETS remill_version
    EXPORT remillTargets
  )
endif()
