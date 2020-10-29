# This is only executed once; use a macro (and not a function) so that
# everything defined here does not end up in a separate namespace
macro(main)
  # default build type
  if(WIN32)
    set(CMAKE_BUILD_TYPE Release)
  else()
    if(NOT CMAKE_BUILD_TYPE)
      set(CMAKE_BUILD_TYPE "RelWithDebInfo")
    endif()
  endif()

  # overwrite the default install prefix
  if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    if(DEFINED WIN32)
      set(CMAKE_INSTALL_PREFIX "C:/")
    else()
      set(CMAKE_INSTALL_PREFIX "/usr/local")
    endif()
  endif()

  message(STATUS "Install prefix: ${CMAKE_INSTALL_PREFIX}")

  # generate a compile commands JSON file.
  set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

  #
  # cxx-common
  #
  
  if(NOT DEFINED CXX_COMMON_REPOSITORY_ROOT)
    if(DEFINED ENV{TRAILOFBITS_LIBRARIES})
      set(CXX_COMMON_REPOSITORY_ROOT $ENV{TRAILOFBITS_LIBRARIES}
        CACHE PATH "Location of cxx-common libraries."
      )
    endif()
  endif()

  if(DEFINED CXX_COMMON_REPOSITORY_ROOT)
    set(TOB_CMAKE_INCLUDE "${CXX_COMMON_REPOSITORY_ROOT}/cmake_modules/repository.cmake")
    if(NOT EXISTS "${TOB_CMAKE_INCLUDE}")
      message(FATAL_ERROR "The library repository could not be found!")
    endif()

    include("${TOB_CMAKE_INCLUDE}")

  else()
    message(STATUS "Using system libraries")
  endif()

  #
  # compiler and linker flags
  #

  # Globally set the required C++ standard
  set(CMAKE_CXX_STANDARD 17)
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
