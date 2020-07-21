#!/usr/bin/env bash
set -e
cd `dirname "$0"`/build
../src/run.sh cmake --build .
cp -f ../src/index.html ./tools/lift
cp -f ../src/index.js ./tools/lift