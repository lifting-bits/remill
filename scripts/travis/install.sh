#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

if [[ "${TRAVIS_OS_NAME}" = "linux" ]] ; then 
    $DIR/scripts/travis/install_linux.sh
fi 

if [[ "${TRAVIS_OS_NAME}" = "osx" ]] ; then 
    $DIR/travis/install_macos.sh
fi
