# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

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

    add_custom_target(${name}.bc
        COMMAND ${CMAKE_LLVM_LINK}
                BasicBlock.${name}.bc
                Instructions.${name}.bc
                -o ${name}.bc
        DEPENDS BasicBlock.${name}.bc
                Instructions.${name}.bc
    )

    # Note: `-O0 -g3` is significant here. We need to make sure that we can
    #       recover variables names within `__remill_basic_block` that may have
    #       been lost when the code was compiled.
    add_custom_command(
        OUTPUT  BasicBlock.${name}.bc
        COMMAND ${CMAKE_CXX_COMPILER}
                ${SEMANTICS_CXX_FLAGS}
                -O0 -g3
                -c ${CMAKE_CURRENT_SOURCE_DIR}/BasicBlock.cpp
                -o BasicBlock.${name}.bc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/BasicBlock.cpp
    )
    
    # Note: Some debug info *must* be preserved. This is so that we can have
    #       debug info on lifted blocks that call these inlinable instruction
    #       functions, without LLVM going and complaining about calling an
    #       inlineable function with debug info.
    add_custom_command(
        OUTPUT  Instructions.${name}.bc
        COMMAND ${CMAKE_CXX_COMPILER}
                ${SEMANTICS_CXX_FLAGS}
                -O3 -g0
                -c ${CMAKE_CURRENT_SOURCE_DIR}/Instructions.cpp
                -o Instructions.${name}.bc
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/Instructions.cpp
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
