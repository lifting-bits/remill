#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

cd $DIR/generated/CFG
cp $DIR/remill/CFG/CFG.proto $DIR/generated/CFG

protoc --cpp_out=. CFG.proto
protoc --python_out=. CFG.proto
