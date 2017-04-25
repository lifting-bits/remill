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

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
UBUNTU_RELEASE=`lsb_release -sc`

#sudo apt-get update -yqq
#sudo apt-get upgrade -yqq

# Make sure we have `add-apt-repository`.
sudo apt-get install -y software-properties-common
sudo apt-get install -y build-essential

# Add the CMake repository.
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x

# Update sources list, and then install needed packages.
sudo apt-get update -yqq
sudo apt-get install -y git
sudo apt-get install -y python2.7
sudo apt-get install -y unzip
sudo apt-get install -y cmake
sudo apt-get install -y realpath
sudo apt-get install -y zlib1g-dev 

# Build remill
${DIR}/build.sh
