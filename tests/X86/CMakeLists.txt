# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

find_package(GTEST REQUIRED)

add_custom_target(tests)

macro(COMPILE_X86_TESTS name address_size has_avx has_avx512)
    
    set(FAKE tests_${name}.S)
    
    set(X86_TEST_FLAGS
        -I${PROJECT_SOURCE_DIR}
        -DADDRESS_SIZE_BITS=${address_size}
        -DHAS_FEATURE_AVX=${has_avx}
        -DHAS_FEATURE_AVX512=${has_avx512}
    )
    
    add_executable(lift-${name}-tests
        EXCLUDE_FROM_ALL
        Lift.cpp
        Tests.S
        ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Arch.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Arch.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Instruction.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
        ${PROJECT_SOURCE_DIR}/remill/CFG/BlockHasher.cpp
        ${PROJECT_SOURCE_DIR}/remill/CFG/CFG.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/Lifter.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/Util.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/IntrinsicTable.cpp
        ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
        ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
        ${PROJECT_SOURCE_DIR}/third_party/murmurhash/MurmurHash2.cpp
    )
    
    target_compile_options(lift-${name}-tests
        PRIVATE ${X86_TEST_FLAGS}
                -DIN_TEST_GENERATOR
    )

    target_link_libraries(lift-${name}-tests
        ${GFLAGS_LIBRARIES}
        ${GLOG_LIBRARIES}
        ${XED_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        ${LLVM_LIBS}
    )
    
    add_executable(run-${name}-tests
        EXCLUDE_FROM_ALL
        Run.cpp
        Tests.S
        tests_${name}.S
        ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Arch.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Arch.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Instruction.cpp
        ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
        ${PROJECT_SOURCE_DIR}/remill/CFG/BlockHasher.cpp
        ${PROJECT_SOURCE_DIR}/remill/CFG/CFG.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/Lifter.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/Util.cpp
        ${PROJECT_SOURCE_DIR}/remill/BC/IntrinsicTable.cpp
        ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
        ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
        ${PROJECT_SOURCE_DIR}/third_party/murmurhash/MurmurHash2.cpp
    )
    
    add_custom_command(
        OUTPUT tests_${name}.bc
        COMMAND lift-${name}-tests
                --arch ${name}
                --bc_out tests_${name}.bc
        DEPENDS lift-${name}-tests
    )
    
    add_custom_command(
        OUTPUT  tests_${name}.S
        COMMAND ${CMAKE_CXX_COMPILER}
                -S -O0 -g3
                -c tests_${name}.bc
                -o tests_${name}.S
        DEPENDS tests_${name}.bc
    )
    
    target_link_libraries(run-${name}-tests
        ${GFLAGS_LIBRARIES}
        ${GLOG_LIBRARIES}
        ${GTEST_LIBRARIES}
        ${XED_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        ${LLVM_LIBS}
    )
    
    target_compile_options(run-${name}-tests
        PRIVATE ${X86_TEST_FLAGS}
    )
    
    add_dependencies(tests lift-${name}-tests run-${name}-tests)
    
endmacro()

if(LINUX)
    COMPILE_X86_TESTS(x86 32 0 0)
    COMPILE_X86_TESTS(x86_avx 32 1 0)
    COMPILE_X86_TESTS(amd64 64 0 0)
    COMPILE_X86_TESTS(amd64_avx 64 1 0)
endif(LINUX)
