# Try to find the XED library
#
# If successful, the following variables will be defined:
# XED_INCLUDE_DIR
# XED_LIBRARY
# XED_STATIC_LIBRARY
# XED_FOUND
#
# Additionally, one of the following import targets will be defined:
# XED::libxed_shared
# XED::libxed_static

# Find the XED library
set(CMAKE_FIND_DEBUG_MODE TRUE)
find_path(XED_INCLUDE_DIR NAMES xed-interface.h
  PATH_SUFFIXES xed
)
find_library(XED_LIBRARY NAMES xed libxed)
set(CMAKE_FIND_DEBUG_MODE FALSE)

# Include the XED library
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(
  XED DEFAULT_MSG
  XED_LIBRARY XED_INCLUDE_DIR
)

# If XED_FOUND
if(XED_FOUND)
  if (NOT TARGET XED::XED)
    # Add a library called XED::libxed_shared
    add_library(XED::XED STATIC IMPORTED)
    set_target_properties(XED::XED PROPERTIES
      IMPORTED_LOCATION "${XED_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${XED_INCLUDE_DIR}"
    )
  endif()

  # Mark the XED library as advanced
  mark_as_advanced(XED_INCLUDE_DIR XED_LIBRARY XED_STATIC_LIBRARY)
endif()
