#!/usr/bin/env bash

# This script is a convenience script for generating some assembly code that
# is a template for saving the machine state to a `State` structure.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

CXX=$(which clang++-3.9)
if [[ $? -ne 0 ]] ; then
    CXX=$(which clang++)
fi

pushd /tmp
${CXX} \
    -std=gnu++11 \
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof \
    -Wno-invalid-offsetof \
    -Wno-return-type-c-linkage \
    -m64 -I${DIR} \
    -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=1 \
    $DIR/tests/X86/PrintSaveState.cpp
    
./a.out > $DIR/generated/Arch/X86/SaveState.S
rm ./a.out
popd
