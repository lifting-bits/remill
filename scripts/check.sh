#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

find $DIR/mcsema -name '*.cpp' -exec $DIR/third_party/bin/clang-check -p=$DIR/build -analyze {} \;

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=32 -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=0

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=32 -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=0

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=32 -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=1

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=0

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=0

$DIR/third_party/bin/clang-check -analyze $DIR/mcsema/Arch/X86/Runtime/Instructions.cpp -- \
	-I${DIR} -isystem ${DIR} -std=gnu++11  -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=0 -DHAS_FEATURE_AVX512=1