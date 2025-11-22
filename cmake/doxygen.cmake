# Copyright (c) 2024 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Doxygen documentation generation

option(REMILL_BUILD_DOCS "Build Doxygen documentation" OFF)

if(REMILL_BUILD_DOCS)
  find_package(Doxygen)
  
  if(DOXYGEN_FOUND)
    message(STATUS "Doxygen found: ${DOXYGEN_EXECUTABLE}")
    
    # Set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)
    
    # Configure the Doxyfile
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    
    # Create output directory
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen)
    
    # Add custom target for building documentation
    add_custom_target(docs
      COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      COMMENT "Generating API documentation with Doxygen"
      VERBATIM
    )
    
    # Add custom target for cleaning documentation
    add_custom_target(docs-clean
      COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/docs/doxygen
      COMMENT "Cleaning generated documentation"
      VERBATIM
    )
    
    message(STATUS "Doxygen documentation target 'docs' added")
    message(STATUS "Run 'cmake --build build --target docs' to generate documentation")
    
  else()
    message(WARNING "Doxygen not found. Documentation will not be built.")
    message(WARNING "Install Doxygen to enable documentation generation:")
    message(WARNING "  - macOS: brew install doxygen graphviz")
    message(WARNING "  - Ubuntu/Debian: sudo apt-get install doxygen graphviz")
    message(WARNING "  - Windows: Download from https://www.doxygen.nl/download.html")
  endif()
endif()

