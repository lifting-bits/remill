#!/usr/bin/env bash

# This script is a convenience script for generating some assembly code that
# is a template for saving the machine state to a `State` structure.

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

pushd /tmp
$DIR/third_party/bin/clang++ \
    -std=gnu++11 \
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof \
    -m64 -I${DIR} \
    -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=1 \
    $DIR/tests/X86/PrintSaveState.cpp
    
./a.out > $DIR/tests/X86/SaveState.S
popd
