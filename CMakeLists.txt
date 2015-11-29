# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

set(CMAKE_C_COMPILER "${MCSEMA_DIR}/third_party/llvm/build/bin/clang")
set(CMAKE_CXX_COMPILER "${MCSEMA_DIR}/third_party/llvm/build/bin/clang")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${MCSEMA_DIR}/third_party/llvm/build/share/llvm/cmake/)

set(LLVM_INSTALL_PREFIX ${MCSEMA_DIR}/third_party/llvm/build)
set(_LLVM_CMAKE_DIR ${MCSEMA_DIR}/third_party/llvm/build/share/llvm/cmake)
set(_LLVM_LIBRARY_DIR "${LLVM_INSTALL_PREFIX}/lib")

# Find LLVM.
find_package(LLVM REQUIRED Config)
#include(LLVMConfig)
#include(AddLLVM)

# Add LLVM includes.
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

link_directories(${MCSEMA_DIR}/third_party/llvm/build/lib)
set(LLVM_LIBRARY_DIRS ${MCSEMA_DIR}/third_party/llvm/build/lib)

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

file(MAKE_DIRECTORY ${MCSEMA_DIR}/build)
file(MAKE_DIRECTORY ${MCSEMA_DIR}/build/lib)
file(COPY ${MCSEMA_DIR}/generated/Arch DESTINATION ${MCSEMA_DIR}/build/lib)

# Generic compiler options.
add_compile_options(-Wall)
add_compile_options(-Werror)
add_compile_options(-pedantic)
add_compile_options(-DMCSEMA_DIR="${MCSEMA_DIR}")

add_executable(cfg_to_bc
    ${MCSEMA_DIR}/mcsema/Translate.cpp
    ${MCSEMA_SOURCE_FILES}
)

llvm_map_components_to_libnames(llvm_libs x86desc x86info x86utils irreader bitreader bitwriter transformutils scalaropts ipo)
 
target_link_libraries(cfg_to_bc
    xed
    protobuf
    glog
    gflags
    stdc++
	${llvm_libs}
)

target_compile_options(cfg_to_bc PRIVATE
    -std=gnu++11
    -frtti
    -g3
    -m64
)
