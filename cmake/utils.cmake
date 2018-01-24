cmake_minimum_required(VERSION 3.2)

function(FindAndSelectClangCompilerUnix)
  if(DEFINED ENV{LLVM_INSTALL_PREFIX})
    set(LLVM_INSTALL_PREFIX $ENV{LLVM_INSTALL_PREFIX} PARENT_SCOPE)
  endif()

  if(DEFINED LLVM_INSTALL_PREFIX)
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/lib/cmake/llvm/")
    list(APPEND FINDPACKAGE_LLVM_HINTS "${LLVM_INSTALL_PREFIX}/share/llvm/cmake/")

    message(STATUS "Using LLVM_INSTALL_PREFIX hints for find_package(LLVM): ${FINDPACKAGE_LLVM_HINTS}")
  endif()

  # it is important to avoid re-defining these variables if they have been already
  # set or you risk ending up in a configure loop!
  if(NOT DEFINED CMAKE_C_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang"
        CACHE PATH "Path to clang binary." PARENT_SCOPE)
    else()
      set(CMAKE_C_COMPILER "clang" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_CXX_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++"
        CACHE PATH "Path to clang++ binary." PARENT_SCOPE)
    else()
      set(CMAKE_CXX_COMPILER "clang++" PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_ASM_COMPILER)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_ASM_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang++"
        CACHE PATH "Path to assembler (aka clang) binary." PARENT_SCOPE)
    else()
      set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER} PARENT_SCOPE)
    endif()
  endif()

  if(NOT DEFINED CMAKE_LLVM_LINK)
    if(DEFINED LLVM_INSTALL_PREFIX)
      set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link"
        CACHE PATH "Path to llvm-link binary." PARENT_SCOPE)
    else()
      set(CMAKE_LLVM_LINK "llvm-link" PARENT_SCOPE)
    endif()
  endif()
endfunction()

function(FindAndSelectClangCompilerWindows)
  message(FATAL_ERROR "todo")
endfunction()

function(FindAndSelectClangCompiler)
  if(UNIX)
    FindAndSelectClangCompilerUnix()
  else()
    FindAndSelectClangCompilerWindows()
  endif()
endfunction()
