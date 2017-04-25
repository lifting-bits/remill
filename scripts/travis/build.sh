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

set -e

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))
BUILD_DIR=${DIR}/build
LLVM_DIR=llvm

ARCH=$(uname -m)
LLVM_VER=3.9.0

case $(uname -s) in
  Darwin)
    OS=apple-darwin
    FILE=clang+llvm-${LLVM_VER}-${ARCH}-${OS}.tar.xz
    ;;
  Linux)
    OS=linux-gnu
    DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    DIST_VERSION=$(lsb_release -sr)
    if [ $DIST_VERSION == "15.04" ]; then
      DIST_VERSION="14.04"
    fi
    FILE=clang+llvm-${LLVM_VER}-${ARCH}-${OS}-${DISTRO}-${DIST_VERSION}.tar.xz
    ;;
  *)
    echo '[!] Unsupported OS'
    exit 1
    ;;
esac

echo "[+] Creating '${BUILD_DIR}'"
mkdir -p ${BUILD_DIR}
pushd ${BUILD_DIR}

if [ ! -f ${FILE} ]; then
  echo "[+] Downloading Clang+LLVM.."
  wget http://llvm.org/releases/${LLVM_VER}/${FILE}

  if [ "$?" != "0" ]; then
    echo "[!] Unsupported operating system."
    echo "[!]  Check http://llvm.org/releases/${LLVM_VER}/ to see what LLVM"
    echo "[!]  packages are available."
    exit 2
  fi
fi

if [ ! -d ${LLVM_DIR} ]; then
  echo "[+] Extracting.."
  mkdir ${LLVM_DIR}
  tar xf ${FILE} -C ${LLVM_DIR} --strip-components=1 
fi

LLVM_DIR=${BUILD_DIR}/${LLVM_DIR}
LLVM_DIR=$(realpath ${LLVM_DIR})
export LLVM_INSTALL_PREFIX=${LLVM_DIR}

if [ ! -d ${BUILD_DIR}/cxx-common ]; then
  echo "[+] Getting cxx-common"
  git clone https://github.com/trailofbits/cxx-common.git
fi

echo "[+] Installing cxx-common"
export TRAILOFBITS_LIBRARIES=${BUILD_DIR}/libraries
mkdir -p ${TRAILOFBITS_LIBRARIES}
export CC=${LLVM_INSTALL_PREFIX}/bin/clang
export CXX=${LLVM_INSTALL_PREFIX}/bin/clang++
${BUILD_DIR}/cxx-common/build.sh --targets xed,glog,gflags,gtest ${TRAILOFBITS_LIBRARIES}


export CC=
export CXX=

echo "[+] Running cmake"
cmake ${DIR}
echo "[+] Building"
make build_x86_tests
