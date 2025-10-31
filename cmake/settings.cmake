# This is only executed once; use a macro (and not a function) so that
# everything defined here does not end up in a separate namespace
macro(main)
  # Set default build type to Debug for single-config generators
  if(NOT CMAKE_BUILD_TYPE AND NOT GENERATOR_IS_MULTI_CONFIG)
      set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
      message(STATUS "CMAKE_BUILD_TYPE not specified, defaulting to Debug")
  endif()

  # overwrite the default install prefix
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(DEFINED WIN32)
      set(CMAKE_INSTALL_PREFIX "C:/remill/install")
    else()
      set(CMAKE_INSTALL_PREFIX "/usr/local")
    endif()
  endif()

  message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

  # generate a compile commands JSON file.
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

  #
  # compiler and linker flags
  #

  # Globally disable C++ language extensions
  set(CMAKE_CXX_EXTENSIONS OFF)

  if(UNIX)
    if(APPLE)
      set(PLATFORM_NAME "macos")
    else()
      set(PLATFORM_NAME "linux")
    endif()
  
  elseif(WIN32)
    set(PLATFORM_NAME "windows")

  else()
    message("This platform is not officially supported")
  endif()

  set(SETTINGS_CMAKE_ true)
endmacro()

if(NOT DEFINED SETTINGS_CMAKE_)
  main()
endif()
