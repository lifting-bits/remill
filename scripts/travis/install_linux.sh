#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))
UBUNTU_RELEASE=`lsb_release -sc`

# Add the CMake repository.
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x

# Update sources list, and then install needed packages.
sudo apt-get update -qq
sudo apt-get install -y git
sudo apt-get install -y libgoogle-glog-dev
sudo apt-get install -y libgtest-dev
sudo apt-get install -y libprotoc-dev
sudo apt-get install -y libprotobuf-dev
sudo apt-get install -y libprotobuf-dev
sudo apt-get install -y protobuf-compiler
sudo apt-get install -y python2.7
sudo apt-get install -y python-pip
sudo apt-get install -y llvm-3.9-dev
sudo apt-get install -y clang-3.9
sudo apt-get install -y g++-multilib
sudo apt-get install -y unzip
sudo apt-get install -y cmake
sudo apt-get install -y realpath

# Upgrade PIP and install the python bindings for protocol buffers.
sudo pip install --upgrade pip
sudo pip install python-magic
sudo pip install 'protobuf==2.4.1'

# Build remill
$DIR/build.sh
