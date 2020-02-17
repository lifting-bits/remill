#!/usr/bin/env bash
set -e
cd `dirname "$0"`
rm -rf build
mkdir -p build
cd build
../src/run.sh bash -c 'cmake -Wno-dev -GNinja -DCMAKE_TOOLCHAIN_FILE="$EM_TOOLCHAIN" ../..'