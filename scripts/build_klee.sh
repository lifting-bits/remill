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

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SRC_DIR=$( cd "$( dirname "${SCRIPTS_DIR}" )" && pwd )
CURR_DIR=$( pwd )

function CloneMcSema {
  if [[ ! -d "${SRC_DIR}/tools/mcsema" ]] ; then
    pushd "${SRC_DIR}/tools"
    git clone --single-branch --branch master --depth 1 git@github.com:trailofbits/mcsema.git
    popd
  fi
}

function BuildRemillAndMcSema {
  CloneMcSema
  "${SCRIPTS_DIR}/build.sh" --llvm-version 3.9 --build-dir "${CURR_DIR}/remill-build"
}

function SetEnvVars {
  export TRAILOFBITS_LIBRARIES="${CURR_DIR}/remill-build/libraries/"
  export CC="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang"
  export CXX="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang++"
  export CXXFLAGS="-fno-rtti -fno-exceptions"
}

function CloneAndBuildKleeUcLibC {
  if [[ ! -d "${CURR_DIR}/klee-uclibc" ]] ; then
    git clone --depth 1 git@github.com:klee/klee-uclibc.git
  fi

  pushd klee-uclibc
  ./configure --make-llvm-lib --with-llvm-config="${TRAILOFBITS_LIBRARIES}/llvm/bin/llvm-config"
  make -j4
  popd
}

function CloneAndBuildKlee {
  CloneAndBuildKleeUcLibC

  if [[ ! -d "klee" ]] ; then
    git clone --single-branch --branch llvm_39 --depth 1 git@github.com:jirislaby/klee.git
  fi

  mkdir -p klee-build
  pushd klee-build
  cmake \
      -DLLVM_CONFIG_BINARY=${TRAILOFBITS_LIBRARIES}/llvm/bin/llvm-config \
      -DENABLE_UNIT_TESTS=OFF \
      -DENABLE_SYSTEM_TESTS=OFF \
      -DLLVM_ENABLE_RTTI=OFF \
      -DENABLE_POSIX_RUNTIME=ON \
      -DENABLE_KLEE_UCLIBC=ON \
      -DENABLE_SOLVER_STP=OFF \
      -DENABLE_SOLVER_Z3=ON \
      -DKLEE_UCLIBC_PATH="${CURR_DIR}/klee-uclibc" \
      "${CURR_DIR}/klee"
  make -j4
  popd
}

function MakeKleeUcLibCModule {
  if [[ ! -f "${CURR_DIR}/libc.bc" ]] ; then
    find klee-uclibc/libc/ -name '*.os' -exec "${TRAILOFBITS_LIBRARIES}/llvm/bin/llvm-link" -o "${CURR_DIR}/libc.bc" {} \+
  fi
}

function main {
  cd "${CURR_DIR}"
  BuildRemillAndMcSema
  SetEnvVars
  CloneAndBuildKlee
  MakeKleeUcLibCModule
  return 0
}

main $@
exit $?
