#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

cp $DIR/remill/CFG/CFG.proto $DIR/generated/CFG
cp $DIR/remill/CFG/CFG.proto $DIR/tools/remill_disass

mkdir -p $DIR/remill/CFG/CFG
cd $DIR/generated/CFG
protoc --cpp_out=. CFG.proto

cd $DIR/tools/remill_disass
protoc --python_out=. CFG.proto
