#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
RESET=`tput sgr0`

# Fetch all dependencies.
echo "${GREEN}Updating aptitude.${RESET}"
sudo apt-get update

echo "${GREEN}Downloading dependencies.${RESET}"
sudo apt-get install -y binutils-dev build-essential
sudo apt-get install -y cmake
sudo apt-get install -y libgflags-dev libgflags2
sudo apt-get install -y libgoogle-glog-dev libgoogle-glog0
sudo apt-get install -y protobuf-compiler libprotobuf-dev libprotobuf8 python-protobuf

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

# Versions of things.
LLVM_VERSION=3.7.0
PIN_VERSION=2.14-71313-gcc.4.4.7-linux

PIN_URL=http://software.intel.com/sites/landingpage/pintool/downloads/pin-${PIN_VERSION}.tar.gz
LLVM_URL=http://llvm.org/releases/${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-linux-gnu-ubuntu-14.04.tar.xz

source $DIR/scripts/bootstrap_common.sh

