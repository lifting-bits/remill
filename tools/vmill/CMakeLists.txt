# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_executable(vmill-snapshot
    Snapshot.cpp
    Arch/X86/Snapshot.cpp
    Snapshot/Snapshot.cpp
)

target_link_libraries(vmill-snapshot
    remill
)

add_compile_options(
    -DINSTALL_RUNTIME_DIR="${CMAKE_INSTALL_PREFIX}/share/vmill/runtime/"
    -DBUILD_RUNTIME_DIR="${CMAKE_CURRENT_BINARY_DIR}/tools/vmill/Runtime/"
)

add_executable(vmill-exec
    Arch/X86/Snapshot.cpp
    BC/Manager.cpp
    BC/Translator.cpp
    CFG/Decoder.cpp
    Context/AddressSpace.cpp
    Context/Context.cpp
    Snapshot/Snapshot.cpp
    Execute.cpp
)

target_link_libraries(vmill-exec
    dl
    m
    remill
    
    LLVMMC
    LLVMTarget
    LLVMCodeGen
    LLVMX86Info
    LLVMX86Utils
    LLVMX86CodeGen
    LLVMX86AsmPrinter
    LLVMRuntimeDyld
    LLVMMCJIT
)

add_custom_target(runtime)
add_dependencies(runtime semantics)

add_subdirectory(Runtime)

add_dependencies(vmill-snapshot runtime)

install(
    TARGETS vmill-snapshot vmill-exec
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
