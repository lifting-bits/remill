# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

find_package(GTEST REQUIRED)

enable_testing()

add_custom_target(build_x86_tests)

macro(COMPILE_X86_TESTS name address_size has_avx has_avx512)
        
    set(X86_TEST_FLAGS
        -I${PROJECT_SOURCE_DIR}
        -DADDRESS_SIZE_BITS=${address_size}
        -DHAS_FEATURE_AVX=${has_avx}
        -DHAS_FEATURE_AVX512=${has_avx512}
        -DGTEST_HAS_RTTI=0
        -DGTEST_HAS_TR1_TUPLE=0
    )
    
    add_executable(lift-${name}-tests
        EXCLUDE_FROM_ALL
        Lift.cpp
        Tests.S
    )
    
    target_compile_options(lift-${name}-tests
        PRIVATE ${X86_TEST_FLAGS}
                -DIN_TEST_GENERATOR
    )

    target_link_libraries(lift-${name}-tests
        remill
    )
    
    add_executable(run-${name}-tests
        EXCLUDE_FROM_ALL
        Run.cpp
        Tests.S
        tests_${name}.S
    )
    
    add_custom_command(
        OUTPUT tests_${name}.bc
        COMMAND lift-${name}-tests
                --arch ${name}
                --bc_out tests_${name}.bc
        DEPENDS lift-${name}-tests semantics
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
        ${GTEST_LIBRARIES}
        remill
    )
    
    target_compile_options(run-${name}-tests
        PRIVATE ${X86_TEST_FLAGS}
    )
    
    add_dependencies(build_x86_tests
        lift-${name}-tests
        run-${name}-tests
    )
    
    add_test(${name} run-${name}-tests)
endmacro()

if(NOT APPLE)
    COMPILE_X86_TESTS(x86 32 0 0)
    COMPILE_X86_TESTS(x86_avx 32 1 0)
endif()

COMPILE_X86_TESTS(amd64 64 0 0)
COMPILE_X86_TESTS(amd64_avx 64 1 0)
