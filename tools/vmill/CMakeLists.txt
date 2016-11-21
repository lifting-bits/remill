# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

add_executable(vmill-snapshot
    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Arch/X86/System32.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot/Snapshot.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/OS/System32.cpp
    
    ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
)

target_link_libraries(vmill-snapshot
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
)

add_executable(vmill-exec32
    ${PROJECT_SOURCE_DIR}/remill/Arch/Arch.cpp
    ${PROJECT_SOURCE_DIR}/remill/Arch/Instruction.cpp
    ${PROJECT_SOURCE_DIR}/remill/Arch/Name.cpp
    ${PROJECT_SOURCE_DIR}/remill/Arch/X86/Arch.cpp
    ${PROJECT_SOURCE_DIR}/remill/BC/Util.cpp
    ${PROJECT_SOURCE_DIR}/remill/CFG/CFG.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/FileSystem.cpp
    ${PROJECT_SOURCE_DIR}/remill/OS/OS.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Arch/X86/System32.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/BC/Lifter.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/BC/Translator.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/ByteCode/Cache.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/ByteCode/Compiler.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/ByteCode/Interpreter.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/ByteCode/Operation.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/ByteCode/VM.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Emulator/Emulator.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Execute32.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/OS/System32.cpp
    ${PROJECT_SOURCE_DIR}/tools/vmill/Snapshot/Snapshot.cpp
)

target_link_libraries(vmill-exec32
    ${GFLAGS_LIBRARIES}
    ${GLOG_LIBRARIES}
    ${XED_LIBRARIES}
    ${PROTOBUF_LIBRARIES}
    ${LLVM_LIBS}
)

install(
    TARGETS vmill-snapshot vmill-exec32
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
)
