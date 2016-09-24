# - Try to find the XED library
#
# This module defines the following variables
#
# XED_FOUND - Was XED found
# XED_INCLUDE_DIR - the XED include directories
# XED_LIBRARIES - Link to this
#
# This module accepts the following variables
#
# XED_ROOT - Can be set to XED install path or Windows build path
#

if (NOT DEFINED XED_ROOT)
    set (XED_ROOT /usr/local)
endif (NOT DEFINED XED_ROOT)

macro (_FIND_XED_LIBRARIES _var)
    find_library (${_var}
        NAMES  ${ARGN}
        HINTS  /usr/local/lib
        PATH_SUFFIXES lib
    )
    mark_as_advanced(${_var})
endmacro ()

macro (_XED_APPEND_LIBRARIES _list _release)
    set(_debug ${_release}_DEBUG)
    if(${_debug})
        set(${_list} ${${_list}} optimized ${${_release}} debug ${${_debug}})
    else()
        set(${_list} ${${_list}} ${${_release}})
    endif()
endmacro ()

# Linux/OS X builds
find_path(XED_INCLUDE_DIR NAMES "intel/xed-interface.h"
    PATHS ${GLOG_ROOT}/include
          /usr/include
          /opt/local/include
)

# Find the libraries
# Linux/OS X builds
if (UNIX)
  _FIND_XED_LIBRARIES(XED_LIBRARIES libxed.so libxed-ild.so)
endif (UNIX)

if (APPLE)
  _FIND_XED_LIBRARIES(XED_LIBRARIES libxed.a libxed-ild.a)
endif (APPLE)

set(XED_INCLUDE_DIRS ${XED_INCLUDE_DIR})

# Linux/OS X builds
string(REGEX REPLACE "/libxed.so" "" XED_LIBRARIES_DIR ${XED_LIBRARIES})
string(REGEX REPLACE "/libxed-ild.so" "" XED_LIBRARIES_DIR ${XED_LIBRARIES})

if (XED_FOUND)
    # _XED_APPEND_LIBRARIES(XED XED_LIBRARIES)
endif ()