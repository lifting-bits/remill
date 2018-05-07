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

SetupLinux() {
  printf "Getting dependencies for platform: linux\n"

  printf " > Adding i386 architecture support\n"
  sudo dpkg --add-architecture i386

  printf " > Updating the system...\n"
  sudo apt-get -qq update
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n"
    return 1
  fi

  printf " > Installing the required packages...\n"
  sudo apt-get install -qqy \
     git \
     cmake \
     python2.7 python-pip python-virtualenv \
     curl \
     build-essential \
     gcc-multilib g++-multilib \
     libtinfo-dev \
     lsb-release \
     realpath \
     zip liblzma-dev zlib1g-dev \
     gnat

  if [ $? -ne 0 ] ; then
    printf " x Could not install the required dependencies\n"
    return 1
  fi

  sudo apt-get install -qqy zlib1g-dev:i386
  if [ $? -ne 0 ] ; then
    printf " x Could not install the i386 dependencies\n"
    return 1
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

SetupMaxOSX() {
  printf "Getting dependencies for platform: osx\n"
  printf " x This platform is not yet supported\n"
  return 1
}

main() {
  # macOS packages.
  if [[ "$OSTYPE" == "darwin"* ]]; then
    SetupMaxOSX
    return $?

  # Linux
  elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    SetupLinux
    return $?

  # Unsupported.
  else
    printf "Getting dependencies for platform: $OSTYPE\n"
    printf " x This platform is not yet supported\n"
    return 1
  fi
}

main $@
exit $?
