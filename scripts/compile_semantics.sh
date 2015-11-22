#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

cd $DIR
CXXFLAGS="-std=gnu++11 -g0 -O0 -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -I${DIR}"
$DIR/third_party/llvm/build/bin/clang++ -x c++ -m32 -DADDRESS_SIZE_BITS=32 $CXXFLAGS -E - \
    < $DIR/mcsema/Arch/X86/Semantics/MACHINE.inc \
    > $DIR/generated/Arch/X86/Semantics/MACHINE32.cpp
    
$DIR/third_party/llvm/build/bin/clang++ -x c++ -m64 -DADDRESS_SIZE_BITS=64  $CXXFLAGS -E - \
    < $DIR/mcsema/Arch/X86/Semantics/MACHINE.inc \
    > $DIR/generated/Arch/X86/Semantics/MACHINE64.cpp

$DIR/third_party/llvm/build/bin/clang++ -g3 -m32 -DADDRESS_SIZE_BITS=32 $CXXFLAGS -emit-llvm \
    -c $DIR/generated/Arch/X86/Semantics/MACHINE32.cpp \
    -o $DIR/generated/Arch/X86/Semantics/MACHINE32.bc

$DIR/third_party/llvm/build/bin/clang++ -g3 -m64 -DADDRESS_SIZE_BITS=64 $CXXFLAGS -emit-llvm \
    -c $DIR/generated/Arch/X86/Semantics/MACHINE64.cpp \
    -o $DIR/generated/Arch/X86/Semantics/MACHINE64.bc
