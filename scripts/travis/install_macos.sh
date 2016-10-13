#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

brew install git
brew install cmake
brew install glog
brew install protobuf
brew install python
brew install coreutils
brew install unzip

$DIR/build.sh
