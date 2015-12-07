# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(mcsema)
cmake_minimum_required (VERSION 2.8)

enable_language(ASM)

set(CMAKE_C_COMPILER "${MCSEMA_DIR}/third_party/bin/clang")
set(CMAKE_CXX_COMPILER "${MCSEMA_DIR}/third_party/bin/clang++")
set(CMAKE_ASM_COMPILER "${MCSEMA_DIR}/third_party/bin/clang")


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
    -Wall -Werror -pedantic
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof
    -DMCSEMA_DIR="${MCSEMA_DIR}" -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS
    -fno-rtti -DGOOGLE_PROTOBUF_NO_RTTI 
    -std=gnu++11 -g3 -m64
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


function(make_x86_tester suffix arch_name addr_size has_avx has_avx512)
    
    set(MCSEMA_ARCH_FLAGS
        -DADDRESS_SIZE_BITS=${addr_size}
        -DHAS_FEATURE_AVX=${has_avx}
        -DHAS_FEATURE_AVX512=${has_avx512}
    )
    
    # Start by making the test generator itself.
    add_executable(gen_test_cfg_${suffix}
        ${MCSEMA_DIR}/tests/X86/Generate.cpp
        ${MCSEMA_DIR}/tests/X86/Tests.S
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
        OUTPUT tests_${suffix}.bc
        COMMAND cfg_to_bc 
           --source_arch=${arch_name} --target_arch=amd64 --os=${MCSEMA_OS_NAME} 
           --cfg=tests_${suffix}.cfg 
           --bc_out=tests_${suffix}.bc
        DEPENDS tests_${suffix}.cfg cfg_to_bc
        COMMENT "Lifting CFG file for tests to tests_${suffix}.bc."
    )
    
    add_custom_command(
        OUTPUT tests_${suffix}.o
        COMMAND ${CMAKE_C_COMPILER} 
           -O3 -m64
           -c tests_${suffix}.bc 
           -o tests_${suffix}.o
        DEPENDS tests_${suffix}.bc
        COMMENT "Compiling lifted test code into tests_${suffix}.o."
    )
    
    add_executable(run_tests_${suffix}
        ${MCSEMA_DIR}/tests/X86/Run.cpp
        ${MCSEMA_DIR}/mcsema/Arch/Runtime/Types.cpp
        ${MCSEMA_DIR}/tests/X86/Tests.S
        tests_${suffix}.o
    )
    
    target_compile_options(run_tests_${suffix} PRIVATE
        ${MCSEMA_ARCH_FLAGS}
    )
    
    target_link_libraries(run_tests_${suffix}
        ${MCSEMA_LIBS}
    )
    
    set_target_properties(run_tests_${suffix}
        PROPERTIES LINK_FLAGS -Wl,-gc-sections
    )
endfunction(make_x86_tester)

#make_x86_tester(x86 x86 32 0 0)
#make_x86_tester(x86_avx x86 32 1 0)
make_x86_tester(amd64 amd64 64 0 0)
make_x86_tester(amd64_avx amd64 64 1 0)
