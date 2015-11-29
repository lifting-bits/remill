# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

set(CMAKE_C_COMPILER "${MCSEMA_DIR}/third_party/bin/clang")
set(CMAKE_CXX_COMPILER "${MCSEMA_DIR}/third_party/bin/clang++")

set(LLVM_INSTALL_PREFIX ${MCSEMA_DIR}/third_party)
set(_LLVM_CMAKE_DIR ${MCSEMA_DIR}/third_party/share/llvm/cmake)
set(_LLVM_LIBRARY_DIR "${LLVM_INSTALL_PREFIX}/lib")

# Find LLVM.
find_package(LLVM REQUIRED Config)

# Find all libraries.
link_directories(${MCSEMA_DIR}/third_party/lib)

# Find all headers.
include_directories(${MCSEMA_DIR})
include_directories(${MCSEMA_DIR}/third_party/include)

# Find all source files.
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
add_compile_options(-DGOOGLE_PROTOBUF_NO_RTTI)
add_compile_options(-D__STDC_CONSTANT_MACROS)
add_compile_options(-D__STDC_LIMIT_MACROS)
add_compile_options(-Wno-nested-anon-types)
add_compile_options(-fno-rtti)

add_executable(cfg_to_bc
    ${MCSEMA_DIR}/mcsema/Translate.cpp
    ${MCSEMA_SOURCE_FILES}
)

llvm_map_components_to_libnames(llvm_libs
    irreader
    bitreader
    bitwriter
    transformutils
    scalaropts
)

target_link_libraries(cfg_to_bc
    libxed.a
    libprotobuf.a
    libgflags.a
    libglog.a
    stdc++
	${llvm_libs}
)

target_compile_options(cfg_to_bc PRIVATE
    -std=gnu++11
    -fno-rtti
    -g3
    -m64
)
