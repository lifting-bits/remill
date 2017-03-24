# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

set(RUNTIME_CXX_FLAGS
    -I${PROJECT_SOURCE_DIR}
    -emit-llvm
    -O3
    -g0
    -emit-llvm
    -std=gnu++11
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
)

macro(COMPILE_RUNTIME os arch)
    set(name ${os}_${arch})

    add_custom_target(${name}.bc
        COMMAND ${CMAKE_LLVM_LINK}
                ${name}_base.bc
                ${PROJECT_BINARY_DIR}/remill/Arch/X86/Runtime/${arch}.bc
                -o ${name}.bc
        DEPENDS ${name}_base.bc
                semantics
    )
    
    add_custom_target(${name}_base.bc
        COMMAND ${CMAKE_CXX_COMPILER}
                ${RUNTIME_CXX_FLAGS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/${name}.cpp
                -o ${name}_base.bc
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/${name}.cpp
    )
    
    add_dependencies(runtime ${name}.bc)
    
    install(
        FILES       ${CMAKE_CURRENT_BINARY_DIR}/${name}.bc
        DESTINATION share/vmill/runtime
    )
endmacro()

COMPILE_RUNTIME(linux x86)
COMPILE_RUNTIME(linux x86_avx)

COMPILE_RUNTIME(linux amd64)
COMPILE_RUNTIME(linux amd64_avx)
