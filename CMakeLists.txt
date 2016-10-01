# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})

project(remill)
cmake_minimum_required (VERSION 3.2)

enable_language(ASM)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

set(LLVM_DIR "/usr/lib/llvm-3.9/lib/cmake/llvm/")
find_package(LLVM 3.9 REQUIRED)
find_package(XED REQUIRED)
find_package(GLOG REQUIRED)
find_package(GFLAGS REQUIRED)
find_package(Protobuf REQUIRED)

include_directories("${LLVM_INCLUDE_DIRS}")
include_directories("${XED_INCLUDE_DIRS}")
include_directories("${GLOG_INCLUDE_DIRS}")
include_directories("${GFLAGS_INCLUDE_DIRS}")
include_directories("${PROTOBUF_INCLUDE_DIRS}")
include_directories("${CMAKE_CURRENT_LIST_DIR}")

if(NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER "${LLVM_INSTALL_PREFIX}/bin/clang-3.9")
endif()

if(NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER ${CMAKE_C_COMPILER})
endif()

if(NOT DEFINED CMAKE_ASM_COMPILER)
    set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
endif()

if(NOT DEFINED CMAKE_LLVM_LINK)
    set(CMAKE_LLVM_LINK "${LLVM_INSTALL_PREFIX}/bin/llvm-link")
endif()

add_definitions(${LLVM_DEFINITIONS})

add_executable(remill-lift
    remill/Lift.cpp
    remill/Arch/X86/Arch.cpp
    remill/Arch/Arch.cpp
    remill/Arch/Instruction.cpp
    remill/CFG/CFG.cpp
    remill/BC/Translator.cpp
    remill/BC/Util.cpp
    remill/BC/IntrinsicTable.cpp
    remill/OS/OS.cpp
)

target_link_libraries(remill-lift
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
    ${XED_LIBRARIES}
    ${PROTOBUF_LIBRARIES}
    
    LLVMIRReader LLVMBitReader LLVMBitWriter
    LLVMTransformUtils
    LLVMScalarOpts
    LLVMSupport
)

target_compile_options(remill-lift PRIVATE
    -x c++

    -Wall
    -Wextra
    -Werror
    -pedantic

    -g3
    -O0
    
    # LLVM headers break these :-(
    #-Wshadow
    #-Wshorten-64-to-32

    -Wno-unused-parameter
    -Wno-c++98-compat
    -Wno-unreachable-code-return
    -Wno-nested-anon-types
    -Wno-extended-offsetof
    -Wno-gnu-anonymous-struct
    -Wno-variadic-macros
    -Wno-gnu-zero-variadic-macro-arguments
    -Wno-gnu-statement-expression
    -Wno-error=unused-command-line-argument
    -Wno-override-module
    -Wno-return-type-c-linkage
    -Wno-c99-extensions
    -Wno-ignored-attributes
      
    -fno-omit-frame-pointer
    -fvisibility-inlines-hidden

    -fno-rtti
    -DGOOGLE_PROTOBUF_NO_RTTI

    -std=gnu++11

    -fPIC
    -fpie
    -m64

    -DINSTALL_SEMANTICS_DIR="${CMAKE_INSTALL_PREFIX}/share/remill/semantics/"
    -DBUILD_SEMANTICS_DIR="${CMAKE_CURRENT_BINARY_DIR}/"
)

add_custom_target(semantics)

macro(COMPILE_X86_SEMANTICS name address_size has_avx has_avx512)
    set(SEMANTICS_CXX_FLAGS

        -I${PROJECT_SOURCE_DIR}
        -emit-llvm
        -DADDRESS_SIZE_BITS=${address_size}
        -DHAS_FEATURE_AVX=${has_avx}
        -DHAS_FEATURE_AVX512=${has_avx512}

        -std=gnu++11
        -stdlib=libc++
        
        -m${address_size}
        
        -Wall
        -Werror
        -Wshadow
        -Wconversion
        -pedantic
        
        -Wshorten-64-to-32
        -Wno-gnu-anonymous-struct
        -Wno-return-type-c-linkage
        -Wno-gnu-zero-variadic-macro-arguments
        -Wno-nested-anon-types
        -Wno-extended-offsetof
        -Wno-gnu-statement-expression
        -Wno-c99-extensions
        -Wno-ignored-attributes

        -ffreestanding

        -fno-vectorize
        -fno-slp-vectorize
        -fno-common
        -fno-builtin
        -fno-exceptions
        -fno-rtti
        -fno-asynchronous-unwind-tables
    )

    # Note: `-O0 -g3` is significant here. We need to make sure that we can
    #       recover variables names within `__remill_basic_block` that may have
    #       been lost when the code was compiled.
    add_custom_target(BasicBlock.${name}.bc
        COMMAND ${CMAKE_CXX_COMPILER}
                ${SEMANTICS_CXX_FLAGS}
                -O0 -g3
                -c ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Runtime/BasicBlock.cpp
                -o BasicBlock.${name}.bc
        SOURCES remill/Arch/X86/Runtime/BasicBlock.cpp
    )

    add_custom_target(Instructions.${name}.bc
        COMMAND ${CMAKE_CXX_COMPILER}
                ${SEMANTICS_CXX_FLAGS}
                -O3 -g0
                -c ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Runtime/Instructions.cpp
                -o Instructions.${name}.bc
        SOURCES remill/Arch/X86/Runtime/Instructions.cpp
    )

    add_custom_target(${name}.bc
        COMMAND ${CMAKE_LLVM_LINK}
                BasicBlock.${name}.bc
                Instructions.${name}.bc
                -o ${name}.bc
        DEPENDS BasicBlock.${name}.bc
                Instructions.${name}.bc
    )

    add_dependencies(semantics ${name}.bc)
    install(
        FILES       ${CMAKE_CURRENT_BINARY_DIR}/${name}.bc
        DESTINATION share/remill/semantics
    )

endmacro()

COMPILE_X86_SEMANTICS(x86 32 0 0)
COMPILE_X86_SEMANTICS(x86_avx 32 1 0)
COMPILE_X86_SEMANTICS(x86_avx512 32 1 1)
COMPILE_X86_SEMANTICS(amd64 64 0 0)
COMPILE_X86_SEMANTICS(amd64_avx 64 1 0)
COMPILE_X86_SEMANTICS(amd64_avx512 64 1 1)

install(
    TARGETS remill-lift
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)