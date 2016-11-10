#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Build and install Google Test.

if [[ "$OSTYPE" == "linux-gnu" ]] ; then
    sudo apt-get install -y libgtest-dev
    mkdir gtest_build
    pushd gtest_build
    cmake /usr/src/gtest
    make
    sudo cp *.a /usr/local/lib
    sudo ldconfig
    popd

elif [[ "$OSTYPE" == "darwin"* ]] ; then
    mkdir gtest_build
    pushd gtest_build
    git clone https://github.com/google/googletest
    cmake googletest/googletest
    make
    ls *.a
    sudo cp *.a /usr/local/lib
    cp -R googletest/googletest/include/gtest ../..
    rm -rf googletest
    popd

else
    printf "Unsupported platform: ${OSTYPE}\n" > /dev/stderr
    exit 1
fi
