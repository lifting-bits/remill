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
UBUNTU_RELEASE=`lsb_release -sc`

#sudo apt-get update -yqq
#sudo apt-get upgrade -yqq

# Make sure we have `add-apt-repository`.
sudo apt-get install -y software-properties-common
sudo apt-get install -y build-essential

# Add the LLVM repositories and keys.
wget -qO - http://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE} main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.8 main"
sudo add-apt-repository -y "deb http://apt.llvm.org/${UBUNTU_RELEASE}/ llvm-toolchain-${UBUNTU_RELEASE}-3.9 main"

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

# Upgrade PIP and install the python bindings for protocol buffers. Ubuntu's
# protobuf-compiler package uses libproto 2.6.1, but facepalmingly, its
# python-protobuf package is based on 2.4.1.
sudo pip install --upgrade pip
sudo pip install python-magic
sudo pip install 'protobuf==2.6.1'

# Build remill
$DIR/build.sh
