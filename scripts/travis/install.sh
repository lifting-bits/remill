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

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

if [[ "${TRAVIS_OS_NAME}" = "linux" ]] ; then
    
    # Print out useful information to see what Linux environment is being used
    # by Travis.
    uname -a
    lsb_release -a

    sudo apt-get update -yqq
    sudo apt-get --force-yes purge isc-dhcp-client
    sudo apt-get install -y isc-dhcp-client
    #sudo apt-get upgrade -yqq
    
    $DIR/scripts/travis/install_linux.sh
fi 

if [[ "${TRAVIS_OS_NAME}" = "osx" ]] ; then 
    $DIR/scripts/travis/install_macos.sh
fi
