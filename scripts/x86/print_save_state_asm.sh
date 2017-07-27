#!/usr/bin/env bash
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script is a convenience script for generating some assembly code that
# is a template for saving the machine state to a `State` structure.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

CXX=$(which c++)

pushd /tmp
${CXX} \
    -std=gnu++11 \
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof \
    -Wno-invalid-offsetof \
    -Wno-return-type-c-linkage \
    -m64 -I${DIR} \
    -DADDRESS_SIZE_BITS=64 -DHAS_FEATURE_AVX=1 -DHAS_FEATURE_AVX512=1 \
    $DIR/tests/X86/PrintSaveState.cpp

mkdir -p $DIR/generated/Arch/X86/

./a.out > $DIR/generated/Arch/X86/SaveState.S
rm ./a.out
popd
