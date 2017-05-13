cmake_minimum_required (VERSION 3.2)
project(x86_runtime BC)

set(X86RUNTIME_SOURCEFILES
    Instructions.cpp
    BasicBlock.cpp
)

set(X86RUNTIME_INCLUDEDIRECTORIES ${CMAKE_SOURCE_DIR})

function (add_runtime_helper target_name address_bit_size enable_avx enable_avx512)
    message(" > Generating target: ${target_name}")

    list(APPEND definitions "HAS_FEATURE_AVX=${enable_avx}")
    list(APPEND definitions "HAS_FEATURE_AVX512=${enable_avx512}")

    add_runtime(${target_name} SOURCES ${X86RUNTIME_SOURCEFILES} ADDRESS_SIZE ${address_bit_size} DEFINITIONS ${definitions})
    target_include_directories(${target_name} PRIVATE "${X86RUNTIME_INCLUDEDIRECTORIES}")
endfunction ()

add_runtime_helper(x86 32 0 0)
add_runtime_helper(x86_avx 32 1 0)
add_runtime_helper(x86_avx512 32 1 1)

if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_runtime_helper(amd64 64 0 0)
    add_runtime_helper(amd64_avx 64 1 0)
    add_runtime_helper(amd64_avx512 64 1 1)
endif ()
