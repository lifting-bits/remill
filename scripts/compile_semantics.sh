#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
BLUE=`tput setaf 4`
RESET=`tput sgr0`

CXXFLAGS=
CXXFLAGS+=" -isystem ${DIR}/third_party/include -I${DIR}"
CXXFLAGS+=" -std=gnu++11 -g0 -O0"
CXXFLAGS+=" -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables"
CXXFLAGS+=" -ffreestanding -fno-common -fno-builtin"
CXXFLAGS+=" -Wall -Werror -Wconversion -pedantic"
CXXFLAGS+=" -Wno-gnu-anonymous-struct -Wno-return-type-c-linkage"
CXXFLAGS+=" -Wno-gnu-zero-variadic-macro-arguments -Wno-nested-anon-types"
CXXFLAGS+=" -Wno-extended-offsetof -Wno-c99-extensions"

function compile_x86()
{
    MACROS="-DADDRESS_SIZE_BITS=$1 -DHAS_FEATURE_AVX=$2 -DHAS_FEATURE_AVX512=$3"
    FILE_NAME=sem
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
    
    printf "${BLUE}${MESSAGE}${RESET}\n"
    
    $DIR/third_party/bin/clang++ -x c++ \
        -emit-llvm -O0 -g0 -m$1 -mtune=generic $MACROS $CXXFLAGS \
        -ffunction-sections -fdata-sections \
	    -c $DIR/remill/Arch/X86/Runtime/Instructions.cpp \
	    -o $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.bc
	    
    $DIR/third_party/bin/clang++ -x c++ \
        -emit-llvm -O0 -g0 -m$1 -mtune=generic $MACROS $CXXFLAGS \
        -ffunction-sections -fdata-sections \
        -c $DIR/remill/Arch/X86/Runtime/BasicBlock.cpp \
        -o $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_block.bc

    $DIR/third_party/bin/clang \
        -emit-llvm -O3 -g0 -m$1 -mtune=generic \
        -ffunction-sections -fdata-sections \
        -c $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.bc \
        -o $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.opt.bc
    
    $DIR/third_party/bin/llvm-link \
        -o=$DIR/generated/${FILE_NAME}.bc \
        $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_block.bc \
        $DIR/generated/Arch/X86/Runtime/${FILE_NAME}_instr.opt.bc
        
    if [[ ! -e $DIR/generated/${FILE_NAME}.bc ]] ; then
        printf "${RED}Error: ${MESSAGE}${RESET}\n"
        exit 1
    fi;
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

exit 0
