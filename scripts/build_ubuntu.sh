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

# Make sure we have `add-apt-repository`.


# Update sources list, and then install needed packages.
sudo apt-get update -yqq
sudo apt-get dist-upgrade -y
sudo apt-get install -y git
sudo apt-get install -y python2.7
sudo apt-get install -y wget
sudo apt-get install -y realpath
sudo apt-get install -y zlib1g-dev
sudo apt-get install -y software-properties-common
sudo apt-get install -y build-essential
sudo apt-get install -y g++-4.9-multilib
sudo apt-get install -y gcc-4.9-multilib

apt-get clean

# General directory structure:
#   /path/to/home/remill
#   /path/to/home/remill-build

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SRC_DIR=$( cd "$( dirname "${SCRIPTS_DIR}" )" && pwd)
PARENT_DIR=$( cd "$( dirname "${SRC_DIR}" )" && pwd)
BUILD_DIR=${PARENT_DIR}/remill-build

# Version name of Ubuntu (e.g. xenial, trusty).
UBUNTU_RELEASE=`lsb_release -sc`

# The version of LLVM that we will use to build remill, and also that remill
# will use to produce bitcode. It's good to match these up.
LLVM_VERSION=llvm40

mkdir -p ${BUILD_DIR}
cd ${BUILD_DIR}

printf "SRC_DIR=${SRC_DIR}\n"
printf "BUILD_DIR=${BUILD_DIR}\n"

# There are pre-build versions of various libraries for specific
# Ubuntu releases.
case ${UBUNTU_RELEASE} in
  xenial)
    OS_VERSION=ubuntu160402
  ;;
  trusty)
    OS_VERSION=ubuntu140405
  ;;
esac

LIBRARY_VERSION=libraries-${LLVM_VERSION}-${OS_VERSION}

# Download CMake.
if [[ ! -d "${BUILD_DIR}/cmake-3.2.0-Linux-x86_64" ]] ; then
  wget https://cmake.org/files/v3.2/cmake-3.2.0-Linux-x86_64.sh
  yes | /bin/bash cmake-3.2.0-Linux-x86_64.sh &>/dev/null
  CMAKE_BIN_DIR=${BUILD_DIR}/cmake-3.2.0-Linux-x86_64/bin
fi

# Download pre-compiled version of cxx-common for this OS. This has things like
# google protobuf, gflags, glog, gtest, capstone, and llvm in it.
if [[ ! -d "${BUILD_DIR}/libraries" ]] ; then
  wget https://s3.amazonaws.com/cxx-common/${LIBRARY_VERSION}.tar.gz
  tar xf ${LIBRARY_VERSION}.tar.gz --warning=no-timestamp
  rm ${LIBRARY_VERSION}.tar.gz

  # Make sure modification times are not in the future.
  find ${BUILD_DIR}/libraries -type f -exec touch {} \;
fi

# Tell the remill CMakeLists.txt where the extracted libraries are. 
export TRAILOFBITS_LIBRARIES=${BUILD_DIR}/libraries

# Configure the remill build, specifying that it should use the pre-built
# Clang compiler binaries.
${CMAKE_BIN_DIR}/cmake \
    -DCMAKE_C_COMPILER=${BUILD_DIR}/libraries/llvm/bin/clang \
    -DCMAKE_CXX_COMPILER=${BUILD_DIR}/libraries/llvm/bin/clang++ \
    ${SRC_DIR}

# Build remill.
make

# Install remill.
sudo make install

# Build and run the x86 test suite.
make build_x86_tests

