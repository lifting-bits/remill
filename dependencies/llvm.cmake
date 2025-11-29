option(LLVM_ENABLE_ASSERTIONS "Enable assertions in LLVM" ON)

# Default values for LLVM_URL and LLVM_SHA256. This is required because "-DLLVM_URL=" would be an empty URL
if("${LLVM_URL}" STREQUAL "")
    set(LLVM_URL "https://github.com/llvm/llvm-project/releases/download/llvmorg-17.0.6/llvm-project-17.0.6.src.tar.xz")
endif()
if("${LLVM_SHA256}" STREQUAL "")
    set(LLVM_SHA256 "58a8818c60e6627064f312dbf46c02d9949956558340938b71cf731ad8bc0813")
endif()

set(LLVM_ARGS
    "-DLLVM_ENABLE_PROJECTS:STRING=lld;clang;clang-tools-extra"
    "-DLLVM_ENABLE_ASSERTIONS:STRING=${LLVM_ENABLE_ASSERTIONS}"
    "-DLLVM_ENABLE_DUMP:STRING=${LLVM_ENABLE_ASSERTIONS}"
    "-DLLVM_ENABLE_RTTI:STRING=ON"
    "-DLLVM_ENABLE_LIBEDIT:STRING=OFF"
    "-DLLVM_PARALLEL_LINK_JOBS:STRING=1"
    "-DLLVM_ENABLE_DIA_SDK:STRING=OFF"
    # This is meant for LLVM development, we use the DYLIB option instead
    "-DBUILD_SHARED_LIBS:STRING=OFF"
    "-DLLVM_LINK_LLVM_DYLIB:STRING=${BUILD_SHARED_LIBS}"
)

# LLVM has a bug on Windows where using clang.exe as the compiler fails to detect
# the host target triple, so we have to specify it manually.
# Reference: https://github.com/lifting-bits/remill/issues/735#issuecomment-3590986077
if(WIN32)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND NOT CMAKE_CXX_COMPILER_FRONTEND_VARIANT MATCHES "^MSVC$")
        message(WARNING
            "Using clang.exe as the compiler on Windows is not well supported.\n"
            "If you run into issues, use clang-cl instead:\n"
            "  cmake -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl ...\n"
        )
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
                set(LLVM_ARCH "aarch64")
            else()
                set(LLVM_ARCH "x86_64")
            endif()
        else()
            set(LLVM_ARCH "i686")
        endif()
        list(APPEND LLVM_ARGS "-DLLVM_HOST_TRIPLE:STRING=${LLVM_ARCH}-pc-windows-msvc")
    endif()
endif()

if(USE_SANITIZERS)
    list(APPEND LLVM_ARGS "-DLLVM_USE_SANITIZER:STRING=Address;Undefined")
endif()

ExternalProject_Add(llvm
    URL
        ${LLVM_URL}
    URL_HASH
        "SHA256=${LLVM_SHA256}"
    CMAKE_CACHE_ARGS
        ${CMAKE_ARGS}
        ${LLVM_ARGS}
    CMAKE_GENERATOR
        "Ninja"
    SOURCE_SUBDIR
        "llvm"
)
