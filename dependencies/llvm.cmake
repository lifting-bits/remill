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
