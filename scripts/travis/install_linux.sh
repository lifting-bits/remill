#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

UBUNTU_RELEASE=`lsb_release -sc`

wget -qO - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

# For LLVM.
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE} main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.8 main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.9 main"

# For CMake
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x

sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     cmake \
     libgoogle-glog-dev \
     libgtest-dev \
     libprotoc-dev libprotobuf-dev libprotobuf-dev protobuf-compiler \
     python2.7 python-pip \
     llvm-3.9-dev clang-3.9 \
     libc++-dev libc++-dev:i386 \
     libc6-dev libc6-dev:i386 \
     unzip

sudo pip install --upgrade pip

sudo pip install python-magic 'protobuf==2.4.1'

./scripts/unix/install_xed.sh

sudo ldconfig

./scripts/unix/compile_protobufs.sh

mkdir build
cd build
cmake ..

make semantics
make all
sudo make install

