# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

enable_language(ASM)

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
add_compile_options(
    -Wall
    -Werror
    -pedantic
    -DMCSEMA_DIR="${MCSEMA_DIR}"
    -DGOOGLE_PROTOBUF_NO_RTTI
    -D__STDC_CONSTANT_MACROS
    -D__STDC_LIMIT_MACROS
    -Wno-nested-anon-types
    -fno-rtti
    -g3
    -m64
    -std=gnu++11
    -Wno-variadic-macros
    -I${MCSEMA_DIR}
)

llvm_map_components_to_libnames(LLVM_LIBS
    irreader
    bitreader
    bitwriter
    transformutils
    scalaropts
)

set(MCSEMA_LIBS
    libxed.a
    libprotobuf.a
    libgflags.a
    libglog.a
    pthread
    stdc++
)

# cfg_to_bc --------------------------------------------------------------------
add_executable(cfg_to_bc
    ${MCSEMA_DIR}/mcsema/Translate.cpp
    ${MCSEMA_SOURCE_FILES}
)

target_link_libraries(cfg_to_bc
    ${MCSEMA_LIBS}
    ${LLVM_LIBS}
)

# run_tests_amd64_avx ----------------------------------------------------------
#add_executable(run_tests_amd64_avx
#    ${MCSEMA_DIR}/tests/X86/Run.cpp
#    ${MCSEMA_DIR}/tests/X86/Tests.S
#)

#target_link_libraries(run_tests_amd64_avx
#    ${MCSEMA_LIBS}
#)

#target_compile_options(run_tests_amd64_avx PRIVATE
#    -DADDRESS_SIZE_BITS=64
#    -DHAS_FEATURE_AVX=1
#)

# gen_test_cfg_amd64_avx -------------------------------------------------------
add_executable(gen_test_cfg_amd64_avx
    ${MCSEMA_DIR}/tests/X86/Generate.cpp
    ${MCSEMA_DIR}/tests/X86/Tests.S
    "${MCSEMA_DIR}/mcsema/CFG/CFG.cpp"
)

target_link_libraries(gen_test_cfg_amd64_avx
    ${MCSEMA_LIBS}
)

target_compile_options(gen_test_cfg_amd64_avx PRIVATE
    -DADDRESS_SIZE_BITS=64
    -DHAS_FEATURE_AVX=1
    -DIN_TEST_GENERATOR
)
