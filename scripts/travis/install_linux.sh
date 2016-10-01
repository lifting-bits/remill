#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))
UBUNTU_RELEASE=`lsb_release -sc`

# Make sure we have `add-apt-repository`.
sudo apt-get update -qq
sudo apt-get upgrade -yqq
sudo apt-get install -y software-properties-common

# Add the LLVM repositories and keys.
wget -qO - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE} main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.8 main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.9 main"

# Add the CMake repository.
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x

# Update sources list, and then install needed packages.
sudo apt-get update -qq
sudo apt-get install -y \
     git \
     libgoogle-glog-dev \
     libgtest-dev \
     libprotoc-dev libprotobuf-dev libprotobuf-dev protobuf-compiler \
     python2.7 python-pip \
     llvm-3.9-dev clang-3.9 \
     libc++-dev libc++-dev:i386 \
     libc6-dev libc6-dev:i386 \
     unzip \
     cmake

# Upgrade PIP and install the python bindings for protocol buffers.
sudo pip install --upgrade pip
sudo pip install python-magic 'protobuf==2.4.1'

# Unpack and install Intel XED.
$DIR/scripts/unix/install_xed.sh

# Compile and install Google Test.
$DIR/scripts/unix/install_gtest.sh

# Compile .proto files into C++ and python files.
$DIR/scripts/unix/compile_protobufs.sh

# Build and install Remill.
mkdir remill_build
pushd remill_build
cmake \
-DCMAKE_C_COMPILER=clang-3.9 \
-DCMAKE_CXX_COMPILER=clang++-3.9 \
-DCMAKE_LLVM_LINK=llvm-link-3.9 \
..

make semantics
make all
sudo make install
popd

