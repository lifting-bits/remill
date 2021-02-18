#
# Copyright (c) 2021-present, Trail of Bits, Inc.
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_INSTALLED_DIRECTORIES "${REMILL_DATA_PATH};.")

string(TOLOWER "${CMAKE_SYSTEM_NAME}" system_name)
if(system_name STREQUAL "darwin")
  set(system_name "macos")
endif()

set(common_include "${CMAKE_CURRENT_LIST_DIR}/system/${system_name}/common.cmake")
if(EXISTS "${common_include}")
  include("${common_include}")
endif()

string(TOLOWER "${CPACK_GENERATOR}" cpack_generator)
include("${CMAKE_CURRENT_LIST_DIR}/system/${system_name}/generators/${cpack_generator}.cmake")
