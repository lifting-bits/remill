#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))


INSTALL_DIR=/usr/local
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
