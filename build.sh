#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
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
echo "[+] Installing Xed"
$DIR/scripts/unix/install_xed.sh
echo "[+] Installing gtest"
$DIR/scripts/unix/install_gtest.sh
echo "[+] Compiling protobufs"
$DIR/scripts/unix/compile_protobufs.sh
echo "[+] Running cmake"

LLVM_DIR=${BUILD_DIR}/${LLVM_DIR}
LLVM_DIR=$(realpath ${LLVM_DIR})
BINDIR=${LLVM_DIR}/bin
LLVM_DIR=${LLVM_DIR}/lib/cmake/llvm

cmake -DLLVM_DIR=${LLVM_DIR} -DCMAKE_C_COMPILER=${BINDIR}/clang -DCMAKE_CXX_COMPILER=${BINDIR}/clang++ -DCMAKE_LLVM_LINK=${BINDIR}/llvm-link ${DIR}
echo "[+] Building semantics"
make semantics
echo "[+] Building remill"
make all
echo "[+] Installing"
sudo make install
