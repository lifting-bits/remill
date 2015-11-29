#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

BLUE=`tput setaf 4`
RESET=`tput sgr0`

CXXFLAGS=
CXXFLAGS="${CXXFLAGS} -std=gnu++11 -g0 -O0 -fno-exceptions -fno-rtti"
CXXFLAGS="${CXXFLAGS} -fno-asynchronous-unwind-tables -I${DIR}" 

compile_x86() {
    MACROS="-DADDRESS_SIZE_BITS=$1 -DHAS_FEATURE_AVX=$2 -DHAS_FEATURE_AVX512=$3"
    FILE_NAME=Semantics
    if [[ $1 -eq 64 ]] ; then
        FILE_NAME="${FILE_NAME}_amd64"
        MESSAGE="Building for AMD64"
    else
        FILE_NAME="${FILE_NAME}_x86"
        MESSAGE="Building for x86"
    fi
    
    if [[ $3 -eq 1 ]] ; then
        MESSAGE="${MESSAGE} with AVX512"
        FILE_NAME="${FILE_NAME}_avx512"
    elif [[ $2 -eq 1 ]] ; then
        MESSAGE="${MESSAGE} with AVX"
        FILE_NAME="${FILE_NAME}_avx"
    fi
    
    echo "${BLUE}${MESSAGE}${RESET}"
    
    $DIR/third_party/bin/clang++ -x c++ \
        -emit-llvm -O3 -m$1 $MACROS $CXXFLAGS \
	    -c $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp \
	    -o $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.bc
	    
    $DIR/third_party/bin/clang++ -x c++ \
        -emit-llvm -O0 -m$1 $MACROS $CXXFLAGS \
        -c $DIR/mcsema/Arch/X86/Runtime/BasicBlock.cpp \
        -o $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_block.bc
    
    $DIR/third_party/bin/llvm-link \
        -o=$DIR/generated/Arch/X86/${FILE_NAME}.bc \
        $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.bc \
        $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_block.bc
}

mkdir -p $DIR/generated/
mkdir -p $DIR/generated/Arch/
mkdir -p $DIR/generated/Arch/X86/
mkdir -p $DIR/generated/Arch/X86/Runtime

compile_x86 32 0 0
compile_x86 32 1 0
compile_x86 32 1 1

compile_x86 64 0 0
compile_x86 64 1 0
compile_x86 64 1 1

