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

# PREFIX comes from `build.sh`.
INSTALL_DIR=${PREFIX}
INSTALL_INCLUDE_DIR=$INSTALL_DIR/include/intel
INSTALL_LIB_DIR=$INSTALL_DIR/lib
XED_RELEASE=2016-02-02

function error()
{
    printf "${1}\n"
    exit 1
}

# Figure out what version of XED to install.
if [[ "$OSTYPE" == "linux"* ]] ; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-lin-x86-64
elif [[ "$OSTYPE" == "darwin"* ]] ; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-mac-x86-64
else
    error "Unsupported platform: ${OSTYPE}"
fi ;

if [[ ! -e $DIR/blob/xed/${XED_VERSION}.zip ]] ; then
    error "Please download XED from ${XED_URL} and place it into ${DIR}/blob/xed/."
fi;

mkdir -p $DIR/third_party
rm -rf $DIR/third_party/xed
unzip $DIR/blob/xed/${XED_VERSION}.zip -d $DIR/third_party/xed

sudo mkdir -p $INSTALL_INCLUDE_DIR
sudo install -t $INSTALL_LIB_DIR $DIR/third_party/xed/kits/${XED_VERSION}/lib/*
sudo install -t $INSTALL_INCLUDE_DIR $DIR/third_party/xed/kits/${XED_VERSION}/include/* 

sudo ldconfig

exit 0
