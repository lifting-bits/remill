#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
RESET=`tput sgr0`

LLVM_VERSION=3.7.0
PIN_VERSION=2.14-71313-clang.5.1-mac

PIN_URL=http://software.intel.com/sites/landingpage/pintool/downloads/pin-${PIN_VERSION}.tar.gz
LLVM_URL=http://llvm.org/releases/${LLVM_VERSION}/clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin.tar.xz

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

source $DIR/scripts/bootstrap_common.sh
