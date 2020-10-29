#!/usr/bin/env bash

set -ex

#export CMAKE_C_COMPILER_LAUNCHER="$(which ccache)"
#export CMAKE_CXX_COMPILER_LAUNCHER="$(which ccache)"

git clone --depth 1 https://github.com/ekilmer/vcpkg-lifting-ports.git
git clone --depth 1 https://github.com/microsoft/vcpkg.git

./vcpkg/bootstrap-vcpkg.sh
./vcpkg/vcpkg install \
  --overlay-ports=vcpkg-lifting-ports/ports \
  --debug \
  --no-binarycaching \
  xed \
  glog \
  gtest \
  gflags \
  "llvm[core,clang,enable-rtti,enable-z3,libcxx,libcxxabi,target-aarch64,target-arm,target-nvptx,target-sparc,target-x86,tools]"

mkdir build && cd build
cmake -G Ninja -DCMAKE_INSTALL_PREFIX=build/install -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake ..
cmake --build .
cmake --build . --target install
cmake --build . --target test_dependencies
env CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test
