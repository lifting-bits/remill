#!/usr/bin/env bash
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ETC_DIR=$(dirname "${DIR}")
VMILL_DIR=$(dirname "${ETC_DIR}")
TOOLS_DIR=$(dirname "${VMILL_DIR}")
REMILL_DIR=$(dirname "${TOOLS_DIR}")

if [[ "${PIN_ROOT}" -eq "" ]] ; then
  PIN_ROOT=/opt/pin-3.2-81205-gcc-linux/
fi

if [[ ! -e "${PIN_ROOT}/pin" ]] ; then
  echo "Could not find PIN at ${PIN_ROOT}. Try to set the PIN_ROOT environment variable."
  exit 1
fi

echo "[+] Compiling program snapshotting pintool"
make \
  TARGET=ia32 \
  PIN_ROOT="${PIN_ROOT}" \
  CXX="g++ -I${REMILL_DIR} -std=gnu++11 " \
  obj-ia32/Snapshot.so
 