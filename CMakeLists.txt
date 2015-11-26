# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

set(CMAKE_C_COMPILER "${MCSEMA_DIR}/third_party/llvm/build/bin/clang")
set(CMAKE_CXX_COMPILER "${MCSEMA_DIR}/third_party/llvm/build/bin/clang")

list(APPEND CMAKE_MODULE_PATH "${MCSEMA_DIR}/third_party/llvm/build/share/llvm/cmake")

# Find LLVM.
include(LLVMConfig)
include(AddLLVM)

# Add LLVM includes.
link_directories(${MCSEMA_DIR}/third_party/llvm/build/lib)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

# Find Protocol Buffers.
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

# Find XED.
include_directories(${MCSEMA_DIR}/third_party/pin/extras/xed-intel64/include)
link_directories(${MCSEMA_DIR}/third_party/pin/extras/xed-intel64/lib)

include_directories(${MCSEMA_DIR}/third_party)

# Find all source files.
include_directories(${MCSEMA_DIR})
file(GLOB MCSEMA_SOURCE_FILES
    "${MCSEMA_DIR}/mcsema/Arch/*.h"
    "${MCSEMA_DIR}/mcsema/Arch/*.cpp"
    
    "${MCSEMA_DIR}/mcsema/Arch/X86/*.h"
    "${MCSEMA_DIR}/mcsema/Arch/X86/*.cpp"
    
    "${MCSEMA_DIR}/mcsema/CFG/*.h"
    "${MCSEMA_DIR}/mcsema/CFG/*.cpp"
    
    "${MCSEMA_DIR}/mcsema/BC/*.h"
    "${MCSEMA_DIR}/mcsema/BC/*.cpp"
)

# Generic compiler options.
add_compile_options(-Wall)
add_compile_options(-Werror)
add_compile_options(-DMCSEMA_DIR="${MCSEMA_DIR}")

add_executable(cfg_to_bc
    ${MCSEMA_DIR}/mcsema/Translate.cpp
    ${MCSEMA_SOURCE_FILES}
)
 
target_link_libraries(cfg_to_bc
    xed
    protobuf
    glog
    gflags
    stdc++
    LLVMX86Desc LLVMX86Info LLVMX86Utils
    LLVMIRReader LLVMBitReader LLVMBitWriter
    LLVMTransformUtils
    LLVMScalarOpts
    LLVMipo
)

target_compile_options(cfg_to_bc PRIVATE
    -std=gnu++11
    -frtti
    -g3
    -m64
)
