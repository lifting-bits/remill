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

# Build and install Google Test.

# PREFIX comes from `build.sh`.
INSTALL_DIR=${PREFIX}

if [[ "$OSTYPE" == "linux-gnu" ]] ; then
    sudo apt-get install -y libgtest-dev
    mkdir -p gtest_build
    pushd gtest_build
    cmake /usr/src/gtest
    make

    if [[ ! -d ${INSTALL_DIR}/lib ]] ; then
        mkdir ${INSTALL_DIR}/lib
    fi

    cp *.a ${INSTALL_DIR}/lib > /dev/null 2>&1 || {
        sudo cp *.a ${INSTALL_DIR}/lib 
    }
    sudo ldconfig
    popd

elif [[ "$OSTYPE" == "darwin"* ]] ; then
    mkdir gtest_build
    pushd -p gtest_build
    git clone https://github.com/google/googletest
    cmake googletest/googletest
    make

    if [[ ! -d ${INSTALL_DIR}/lib ]] ; then
        mkdir ${INSTALL_DIR}/lib
    fi

    ls *.a
    cp *.a ${INSTALL_DIR}/lib > /dev/null 2>&1 || {
        sudo cp *.a ${INSTALL_DIR}/lib 
    }
    cp -R googletest/googletest/include/gtest ../..
    rm -rf googletest
    popd

else
    printf "Unsupported platform: ${OSTYPE}\n" > /dev/stderr
    exit 1
fi
