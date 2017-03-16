# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_executable(vmill-snapshot
    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Arch/X86/Snapshot.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot/Snapshot.cpp
    
    ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
)

target_link_libraries(vmill-snapshot
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
)

#add_executable(vmill-exec32
#    ${PROJECT_SOURCE_DIR}/remill/Arch/Arch.cpp
#    ${PROJECT_SOURCE_DIR}/remill/Arch/Instruction.cpp
#    ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
#    ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Arch.cpp
#    ${PROJECT_SOURCE_DIR}/remill/BC/IntrinsicTable.cpp
#    ${PROJECT_SOURCE_DIR}/remill/BC/Lifter.cpp
#    ${PROJECT_SOURCE_DIR}/remill/BC/Optimizer.cpp
#    ${PROJECT_SOURCE_DIR}/remill/BC/Util.cpp
#    ${PROJECT_SOURCE_DIR}/remill/CFG/CFG.cpp
#    ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
#    ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Arch/X86/Linux32.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/BC/Translator.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/CFG/Decoder.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Executor/Executor.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Executor/Native/Executor.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Executor/Runtime.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Execute.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/OS/Linux/System.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/OS/Linux/SystemCall.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/OS/System.cpp
#    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot/Snapshot.cpp
#)
#
#target_link_libraries(vmill-exec32
#    "-pie"
#    dl
#    m
#    ${GFLAGS_LIBRARIES}
#    ${GLOG_LIBRARIES}
#    ${XED_LIBRARIES}
#    ${PROTOBUF_LIBRARIES}
#    ${LLVM_LIBS}
#    
#    LLVMMC
#    LLVMTarget
#    LLVMCodeGen
#    LLVMX86Info
#    LLVMX86Utils
#    LLVMX86CodeGen
#    LLVMX86AsmPrinter
#    LLVMRuntimeDyld
#    LLVMMCJIT
#)

add_custom_target(runtime)
add_dependencies(runtime semantics)

add_subdirectory(Runtime)

add_dependencies(vmill-snapshot runtime)

install(
    TARGETS vmill-snapshot #vmill-exec32
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
