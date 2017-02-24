# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})

project(remill)
cmake_minimum_required (VERSION 3.2)

enable_language(ASM)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

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

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif()

add_definitions(${LLVM_DEFINITIONS})

add_compile_options(
    -x c++

    -Wall
    -Wextra
    -Werror
    -pedantic

    -g3
    -O0
    
    -Wno-unused-parameter
    -Wno-c++98-compat
    -Wno-unreachable-code-return
    -Wno-nested-anon-types
    -Wno-extended-offsetof
    -Wno-gnu-anonymous-struct
    -Wno-gnu-designator
    -Wno-variadic-macros
    -Wno-gnu-zero-variadic-macro-arguments
    -Wno-gnu-statement-expression
    -Wno-return-type-c-linkage
    -Wno-c99-extensions
    -Wno-ignored-attributes
    -Wno-unused-local-typedef
    
    -fno-omit-frame-pointer
    -fvisibility-inlines-hidden

    -fno-exceptions
    -fno-rtti
    -fno-asynchronous-unwind-tables

    -fno-rtti
    -std=gnu++11
    -fPIC
    -fPIE
    -m64

    -DINSTALL_SEMANTICS_DIR="${CMAKE_INSTALL_PREFIX}/share/remill/semantics/"
    -DBUILD_SEMANTICS_DIR="${CMAKE_CURRENT_BINARY_DIR}/"
    -DGOOGLE_PROTOBUF_NO_RTTI
)

add_executable(remill-lift
    remill/Lift.cpp
    remill/Arch/X86/Arch.cpp
    remill/Arch/Arch.cpp
    remill/Arch/Instruction.cpp
    remill/Arch/Name.cpp
    remill/CFG/CFG.cpp
    remill/BC/Lifter.cpp
    remill/BC/Util.cpp
    remill/BC/IntrinsicTable.cpp
    remill/OS/FileSystem.cpp
    remill/OS/OS.cpp
)

set(LLVM_LIBS
    curses
    LLVMCore
    LLVMSupport
    LLVMAnalysis
    LLVMipo
    LLVMIRReader
    LLVMBitReader
    LLVMBitWriter
    LLVMTransformUtils
    LLVMScalarOpts
)

target_link_libraries(remill-lift
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
    ${XED_LIBRARIES}
    ${PROTOBUF_LIBRARIES}
    ${LLVM_LIBS}
)

add_executable(remill-opt
    remill/Optimize.cpp
    remill/BC/Util.cpp
    remill/BC/IntrinsicTable.cpp
    remill/BC/Optimizer.cpp
    remill/OS/FileSystem.cpp
    remill/OS/OS.cpp
)

target_link_libraries(remill-opt
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
    ${LLVM_LIBS}
    LLVMLTO
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
        
        # TODO(pag): This should be what I do, but I've observed strange LLVM
        #            code gen issues, where 32-bit code whose data layout is
        #            converted to 64-bit code will sometimes miscompile pointers
        #            as 32-bit. This is, of course, in bitcode that doesn't
        #            do any ptrtoint or inttoptr casts! And this issue doesn't
        #            show up when certain amounts of very aggressive
        #            optimizations are performed to the file before converting
        #            to 32-bit >:-(
        # -m${address_size}
        
        -Wall
        -Werror
        -Wshadow
        -Wconversion
        -Wpadded
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

        # All of these are needed to disable vectorization, both in the LLVM
        # optimizer, and in the Clang front-end.
        -mtune=generic
        -mno-sse
        -mno-avx
        -mno-3dnow
        -fno-vectorize
        -fno-slp-vectorize
        
        -ffreestanding
        -fno-common
        -fno-builtin
        -fno-exceptions
        -fno-rtti
        -fno-asynchronous-unwind-tables

        -Wno-unneeded-internal-declaration
        -Wno-unused-function
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
    
    # Note: Some debug info *must* be preserved. This is so that we can have
    #       debug info on lifted blocks that call these inlinable instruction
    #       functions, without LLVM going and complaining about calling an
    #       inlineable function with debug info.
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

# Bring in the tools.
add_subdirectory(${PROJECT_SOURCE_DIR}/tools)

install(
    TARGETS remill-lift remill-opt
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
