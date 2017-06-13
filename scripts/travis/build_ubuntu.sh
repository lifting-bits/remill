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
sudo apt-get install -y software-properties-common
sudo apt-get install -y build-essential

# Add the CMake repository.
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x

# Update sources list, and then install needed packages.
sudo apt-get update -yqq
sudo apt-get dist-upgrade -y
sudo apt-get install -y git \
                        python2.7 \
                        wget \
                        cmake \
                        realpath \
                        zlib1g-dev \
                        build-essential \
                        libstdc++-5-dev \
                        g++-5-multilib \
                        gcc-5-multilib

apt-get clean

# General directory structure:
#   /path/to/home/remill
#   /path/to/home/remill-build

SRC_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BUILD_DIR=$( cd "$( dirname "${SRC_DIR}" )" && pwd)/remill-build
mkdir -p ${BUILD_DIR}

# Switch to the right branch
cd ${SRC_DIR}

# What branch are we building?
BRANCH=master
if [[ "${TRAVIS_BRANCH}" -ne "" ]] ; then
  BRANCH=${TRAVIS_BRANCH}
elif [[ condition ]]; then
  BANCH=${TRAVIS_PULL_REQUEST_BRANCH}
fi
git checkout ${BRANCH}

# Version name of Ubuntu (e.g. xenial, trusty).
UBUNTU_RELEASE=`lsb_release -sc`

# The version of LLVM that we will use to build remill, and also that remill
# will use to produce bitcode. It's good to match these up.
LLVM_VERSION=llvm40

# There are pre-build versions of various libraries for specific
# Ubuntu releases.
case ${UBUNTU_RELEASE} in
  xenial) OS_VERSION=ubuntu160402
  ;;
  trusty) OS_VERSION=ubuntu140405
  ;;
esac

LIBRARY_VERSION=libraries-${LLVM_VERSION}-${OS_VERSION}

cd ${BUILD_DIR}

# Download pre-compiled version of cxx-common for this OS. This has things like
# google protobuf, gflags, glog, gtest, capstone, and llvm in it.
wget https://s3.amazonaws.com/cxx-common/${LIBRARY_VERSION}.tar.gz
tar xf ${LIBRARY_VERSION}.tar.gz
rm ${LIBRARY_VERSION}.tar.gz

# Tell the remill CMakeLists.txt where the extracted libraries are. 
export TRAILOFBITS_LIBRARIES=${BUILD_DIR}/libraries

# Configure the remill build, specifying that it should use the pre-built
# Clang compiler binaries.
cmake -DCMAKE_C_COMPILER=${BUILD_DIR}/libraries/llvm/bin/clang \
      -DCMAKE_CXX_COMPILER=${BUILD_DIR}/libraries/llvm/bin/clang++ \
      ${SRC_DIR}

# Build remill.
make -j8

# Build and run the x86 test suite.
make build_x86_tests -j8

