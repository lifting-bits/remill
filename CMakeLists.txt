# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

project(remill)
cmake_minimum_required (VERSION 3.2)

enable_language(ASM)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

find_package(LLVM 3.9 REQUIRED)
find_package(XED REQUIRED)
find_package(GLOG REQUIRED)
find_package(GFLAGS REQUIRED)
find_package(Protobuf REQUIRED)

include_directories("${PROJECT_SOURCE_DIR}")
include_directories("${LLVM_INCLUDE_DIRS}")
include_directories("${XED_INCLUDE_DIRS}")
include_directories("${GLOG_INCLUDE_DIRS}")
include_directories("${GFLAGS_INCLUDE_DIRS}")
include_directories("${PROTOBUF_INCLUDE_DIRS}")
include_directories("${CMAKE_CURRENT_LIST_DIR}")

set(CMAKE_ASM_COMPILER ${CMAKE_CXX_COMPILER})

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

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
    remill/CFG/BlockHasher.cpp
    remill/CFG/CFG.cpp
    remill/BC/Lifter.cpp
    remill/BC/Util.cpp
    remill/BC/IntrinsicTable.cpp
    remill/OS/FileSystem.cpp
    remill/OS/OS.cpp
    third_party/murmurhash/MurmurHash2.cpp
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
add_subdirectory(remill/Arch/X86/Runtime)
add_dependencies(remill-lift semantics)

add_subdirectory(tests/X86)

install(
    TARGETS remill-lift remill-opt
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)

add_subdirectory(tools)

