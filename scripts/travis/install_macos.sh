#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

brew install glog
brew install protobuf

$DIR/build.sh
