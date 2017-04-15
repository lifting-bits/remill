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

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

cp $DIR/remill/CFG/CFG.proto $DIR/generated/CFG
cp $DIR/remill/CFG/CFG.proto $DIR/tools/remill_disass

mkdir -p $DIR/remill/CFG/CFG
cd $DIR/generated/CFG
protoc --cpp_out=. CFG.proto

cd $DIR/tools/remill_disass
protoc --python_out=. CFG.proto
