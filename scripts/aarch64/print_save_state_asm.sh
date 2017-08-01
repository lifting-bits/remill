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

mkdir -p $DIR/generated/Arch/AArch64

pushd /tmp

${CXX} \
    -std=gnu++11 \
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof \
    -Wno-invalid-offsetof \
    -Wno-return-type-c-linkage \
    -I${DIR} \
    -DADDRESS_SIZE_BITS=64 \
    $DIR/tests/AArch64/PrintSaveState.cpp

./a.out > $DIR/generated/Arch/AArch64/SaveState.S


${CXX} \
    -std=gnu++11 \
    -Wno-nested-anon-types -Wno-variadic-macros -Wno-extended-offsetof \
    -Wno-invalid-offsetof \
    -Wno-return-type-c-linkage \
    -I${DIR} \
    -DADDRESS_SIZE_BITS=64 \
    $DIR/tests/AArch64/PrintRestoreState.cpp

./a.out > $DIR/generated/Arch/AArch64/RestoreState.S

rm ./a.out
popd
