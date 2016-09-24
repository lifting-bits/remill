# - Try to find the Intel XED library
#
# This module defines the following variables
#
# XED_FOUND - Was XED found
# XED_INCLUDE_DIRS - the XED include directories
# XED_LIBRARIES - Link to this
#
# This module accepts the following variables
#
# XED_ROOT - Can be set to XED install path or Windows build path
#

if (NOT DEFINED XED_ROOT)
     set (XED_ROOT /usr /usr/local)
endif (NOT DEFINED XED_ROOT)

set (LIB_PATHS ${XED_ROOT} ${XED_ROOT}/lib)

macro(_FIND_XED_LIBRARIES _var)
     find_library(${_var}
          NAMES  ${ARGN}
          PATHS ${LIB_PATHS} /opt/local/lib
                             /usr/lib/x86_64-linux-gnu
                             /usr/local/lib
                             /usr/lib
          PATH_SUFFIXES lib
      )
     mark_as_advanced(${_var})
endmacro()

macro(_XED_APPEND_LIBRARIES _list _release)
set(_debug ${_release}_DEBUG)
if(${_debug})
     set(${_list} ${${_list}} optimized ${${_release}} debug ${${_debug}})
else()
     set(${_list} ${${_list}} ${${_release}})
endif()
endmacro()


# Linux/OS X builds
find_path(XED_INCLUDE_DIR NAMES intel/xed-interface.h
    PATHS ${XED_ROOT}/include
          /usr/include
          /opt/local/include
)

# Find the libraries
# Linux/OS X builds
if(UNIX)
    _FIND_XED_LIBRARIES(XED_LIBRARIES libxed.so)
endif(UNIX)
if(APPLE)
    _FIND_XED_LIBRARIES(XED_LIBRARIES libxed.a)
endif(APPLE)

if(XED_FOUND)
    message(STATUS "xed library found at ${XED_LIBRARIES}")
endif()

# handle the QUIETLY and REQUIRED arguments and set XED_FOUND to TRUE if
# all listed variables are TRUE
include("${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake")
FIND_PACKAGE_HANDLE_STANDARD_ARGS(XED DEFAULT_MSG
     XED_LIBRARIES)

# Linux/OS X builds
set(XED_INCLUDE_DIRS ${XED_INCLUDE_DIR})
string(REGEX REPLACE "/libxed.so" "" XED_LIBRARIES_DIR ${XED_LIBRARIES})

if(XED_FOUND)
    message(STATUS "Found xed  (include: ${XED_INCLUDE_DIRS}, library: ${XED_LIBRARIES})")
      # _XED_APPEND_LIBRARIES(XED XED_LIBRARIES)
endif()