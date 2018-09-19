# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

project(remill-lift)
cmake_minimum_required(VERSION 3.2)

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/settings.cmake")
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/utils.cmake")

FindAndSelectClangCompiler()

# warnings and compiler settings
if(NOT DEFINED WIN32)
  set(PROJECT_CXXFLAGS
    ${GLOBAL_CXXFLAGS} -Werror -Wconversion -pedantic 
    -Wno-unreachable-code-return 
  )
endif()

#
# target settings
#

set(REMILL_LIFT remill-lift-${REMILL_LLVM_VERSION})

add_executable(${REMILL_LIFT}
  Lift.cpp
)

# this is needed for the #include directives with absolutes paths to work correctly; it must
# also be set to PUBLIC since mcsema-lift includes some files directly
list(APPEND PROJECT_INCLUDEDIRECTORIES ${CMAKE_CURRENT_SOURCE_DIR})

#
# libraries
#

# remill
if(NOT TARGET remill)
  if("${PLATFORM_NAME}" STREQUAL "windows")
    set(REMILL_FINDPACKAGE_HINTS HINTS "${CMAKE_INSTALL_PREFIX}/remill/lib")
  endif()

  find_package(remill REQUIRED ${REMILL_FINDPACKAGE_HINTS})
endif()

list(APPEND PROJECT_LIBRARIES remill)

#
# target settings
#

target_link_libraries(${REMILL_LIFT} PRIVATE ${PROJECT_LIBRARIES})
target_include_directories(${REMILL_LIFT} SYSTEM PUBLIC ${PROJECT_INCLUDEDIRECTORIES})
target_compile_definitions(${REMILL_LIFT} PUBLIC ${PROJECT_DEFINITIONS})
target_compile_options(${REMILL_LIFT} PRIVATE ${PROJECT_CXXFLAGS})

if(DEFINED WIN32)
  set(install_folder "${CMAKE_INSTALL_PREFIX}/remill")
else()
  set(install_folder "${CMAKE_INSTALL_PREFIX}")
endif()

install(
  TARGETS ${REMILL_LIFT}
  RUNTIME DESTINATION "${install_folder}/bin"
  LIBRARY DESTINATION "${install_folder}/lib"
)
