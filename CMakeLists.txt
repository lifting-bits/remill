# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(remill)
cmake_minimum_required (VERSION 2.8)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

enable_language(ASM)

# Third-party libraries.
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

add_definitions(${LLVM_DEFINITIONS})

set(CMAKE_C_COMPILER "clang-3.9")
set(CMAKE_CXX_COMPILER "clang++-3.9")
set(CMAKE_ASM_COMPILER "clang-3.9")

# Generic compiler options.
add_compile_options(
    -Wall
    -Wextra
    -Werror
    -pedantic
    
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
    -std=gnu++11

    -fPIC
    -fpie
    -m64
)

add_executable(remill-lift
    remill/Translate.cpp
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
    LLVM
)
