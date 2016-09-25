#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

function generate_tests()
{
    pushd /tmp
    clang++-3.9 \
        -I${DIR} \
        -std=gnu++11 \
        -Wno-nested-anon-types \
        -Wno-variadic-macros \
        -Wno-extended-offsetof \
        -Wno-return-type-c-linkage \
        -Wno-expansion-to-defined \
        -m64 \
        -I${DIR} \
        -DIN_TEST_GENERATOR \
        -DADDRESS_SIZE_BITS=${1} \
        -DHAS_FEATURE_AVX=${2} \
        -DHAS_FEATURE_AVX512=${3} \
        $DIR/tests/X86/Tests.S \
        $DIR/tests/X86/Generate.cpp \
        $DIR/remill/CFG/CFG.cpp \
        -lxed \
        -lgflags \
        -lglog \
        -lprotobuf
    
    ./a.out > $DIR/generated/Arch/X86/Tests/${4}.cfg
    rm ./a.out
    popd
}

mkdir -p $DIR/generated/Arch/X86/Tests

generate_tests 32 0 0 x86
generate_tests 32 1 0 x86_avx
generate_tests 64 0 0 amd64
generate_tests 64 1 0 amd64_avx
