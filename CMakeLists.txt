# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

enable_language(ASM)

set(CMAKE_C_COMPILER "${MCSEMA_DIR}/third_party/bin/clang")
set(CMAKE_CXX_COMPILER "${MCSEMA_DIR}/third_party/bin/clang++")
set(CMAKE_ASM_COMPILER "${MCSEMA_DIR}/third_party/bin/clang")

# Find LLVM. This is so ugly.
set(LLVM_ROOT "${MCSEMA_DIR}/third_party")
set(_LLVM_CMAKE_DIR "${LLVM_ROOT}/share/llvm/cmake")
list(APPEND CMAKE_PREFIX_PATH "${_LLVM_CMAKE_DIR}")
find_package(LLVM EXACT 3.7.0 REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

include(AddLLVM)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

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
    -Wall -Werror -pedantic
    -Wno-nested-anon-types -Wno-extended-offsetof -Wno-gnu-anonymous-struct
    -Wno-variadic-macros -Wno-gnu-zero-variadic-macro-arguments
    -DMCSEMA_DIR="${MCSEMA_DIR}" -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS
    -fno-rtti -fno-exceptions -DGOOGLE_PROTOBUF_NO_RTTI 
    -std=gnu++11 -g3 -m64
    -I${MCSEMA_DIR}
)

#set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${MCSEMA_DIR}/third_party/lib")

# TODO(pag): This is really ugly.
if(APPLE)
    set(UNWIND_LIB )
    set(STRIP_DEAD_CODE -Wl,-dead_strip)
else()
    set(UNWIND_LIB /usr/lib/x86_64-linux-gnu/libunwind.so.8)
    set(STRIP_DEAD_CODE -Wl,-gc-sections)
endif(APPLE)


link_directories(${MCSEMA_DIR}/third_party/lib)

# Find all libraries. This includes LLVM libraries.
set(MCSEMA_LIBS
    PRIVATE
        ${MCSEMA_DIR}/third_party/lib/libxed.so
        libprotobuf.a
        libgflags.a
        libglog.a
        LLVMIRReader
        LLVMBitReader
        LLVMBitWriter
        LLVMTransformUtils
        LLVMScalarOpts
    PUBLIC
        ${UNWIND_LIB}
        pthread
        stdc++
)

# cfg_to_bc --------------------------------------------------------------------
add_executable(cfg_to_bc
    ${MCSEMA_DIR}/mcsema/Translate.cpp
    ${MCSEMA_SOURCE_FILES}
)

# Some library stuff.
#list(APPEND CMAKE_LIBRARY_PATH ${MCSEMA_DIR}/third_party/lib)
#set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

target_link_libraries(cfg_to_bc
    ${MCSEMA_LIBS}
)

# optimize_bc plugin -----------------------------------------------------------

add_llvm_loadable_module( Optimizer ${MCSEMA_DIR}/mcsema/Optimize.cpp )

# test code --------------------------------------------------------------------

function(make_x86_tester suffix arch_name addr_size has_avx has_avx512)
    
    set(MCSEMA_ARCH_FLAGS
        -DADDRESS_SIZE_BITS=${addr_size}
        -DHAS_FEATURE_AVX=${has_avx}
        -DHAS_FEATURE_AVX512=${has_avx512}
    )
    
    add_custom_command(
        OUTPUT gen_Tests_${suffix}.o
        COMMAND ${MCSEMA_DIR}/third_party/bin/clang
            -m64 -mavx512f -mavx512pf -mavx512er -mavx512cd
            ${MCSEMA_ARCH_FLAGS}
            -DIN_TEST_GENERATOR
            -I${MCSEMA_DIR}
            -c ${MCSEMA_DIR}/tests/X86/Tests.S
            -o gen_Tests_${suffix}.o
        DEPENDS ${MCSEMA_DIR}/tests/X86/Tests.S
        COMMENT "Compiling Tests.S into test generator gen_Tests_${suffix}.o."
    )
    
    # Difference here is the fixed `-m64`. This is so that we can actually run
    # the 64-bit versions of the 32-bit-specific code.
    add_custom_command(
        OUTPUT run_Tests_${suffix}.o
        COMMAND ${MCSEMA_DIR}/third_party/bin/clang
            -m64 -mavx512f -mavx512pf -mavx512er -mavx512cd
            ${MCSEMA_ARCH_FLAGS}
            -I${MCSEMA_DIR}
            -c ${MCSEMA_DIR}/tests/X86/Tests.S
            -o run_Tests_${suffix}.o
        DEPENDS ${MCSEMA_DIR}/tests/X86/Tests.S
        COMMENT "Compiling Tests.S into test runner run_Tests_${suffix}.o."
    )
    
    # Start by making the test generator itself.
    add_executable(gen_test_cfg_${suffix}
        ${MCSEMA_DIR}/tests/X86/Generate.cpp
        gen_Tests_${suffix}.o
        ${MCSEMA_DIR}/mcsema/CFG/CFG.cpp
    )
    
    target_link_libraries(gen_test_cfg_${suffix}
        ${MCSEMA_LIBS}
    )
    
    target_compile_options(gen_test_cfg_${suffix} PRIVATE
        ${MCSEMA_ARCH_FLAGS}
        -DIN_TEST_GENERATOR
    )
    
    add_custom_command(
        OUTPUT tests_${suffix}.cfg
        COMMAND gen_test_cfg_${suffix} --cfg_out=tests_${suffix}.cfg
        DEPENDS gen_test_cfg_${suffix}
        COMMENT "Generating CFG file for tests using gen_test_cfg_${suffix}."
    )
    
    add_custom_command(
        OUTPUT lifted_tests_${suffix}.bc
        COMMAND cfg_to_bc 
            --source_arch=${arch_name} --target_arch=amd64 --os=${MCSEMA_OS_NAME} 
            --cfg=tests_${suffix}.cfg 
            --bc_out=lifted_tests_${suffix}.bc
        DEPENDS tests_${suffix}.cfg cfg_to_bc
        COMMENT "Lifting CFG file for tests to lifted_tests_${suffix}.bc."
    )

    add_custom_command(
        OUTPUT lifted_tests_${suffix}.opt.bc
        COMMAND ${MCSEMA_DIR}/scripts/optimize_bitcode.sh
            lifted_tests_${suffix}.bc
            lifted_tests_${suffix}.opt.bc
        DEPENDS lifted_tests_${suffix}.bc Optimizer
        COMMENT "Optimizing lifted_tests_${suffix}.bc."
    )
    
    add_custom_command(
        OUTPUT lifted_tests_${suffix}.o
        COMMAND ${CMAKE_C_COMPILER} 
            -O3
            -m64
            -Wno-override-module
            -c lifted_tests_${suffix}.opt.bc 
            -o lifted_tests_${suffix}.o
        DEPENDS lifted_tests_${suffix}.opt.bc
        COMMENT "Compiling lifted test code into tests_${suffix}.o."
    )
    
    add_executable(run_tests_${suffix}
        ${MCSEMA_DIR}/tests/X86/Run.cpp
        ${MCSEMA_DIR}/mcsema/Arch/Runtime/Types.cpp
        run_Tests_${suffix}.o
        lifted_tests_${suffix}.o
    )
    
    target_compile_options(run_tests_${suffix} PRIVATE
        ${MCSEMA_ARCH_FLAGS}
    )
    
    target_link_libraries(run_tests_${suffix}
        ${MCSEMA_LIBS}
        libgtest.a
    )
    
    set_target_properties(run_tests_${suffix}
        PROPERTIES LINK_FLAGS ${STRIP_DEAD_CODE}
    )
endfunction(make_x86_tester)

# Make tests that use all features (except AVX512).
make_x86_tester(x86 x86 32 0 0)
make_x86_tester(x86_avx x86 32 1 0)
#make_x86_tester(x86_avx512 x86 32 1 1)
make_x86_tester(amd64 amd64 64 0 0)
make_x86_tester(amd64_avx amd64 64 1 0)
#make_x86_tester(amd64_avx512 amd64 64 1 1)
