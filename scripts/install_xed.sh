#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. Remill root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`

INSTALL_DIR=/usr/local
INSTALL_INCLUDE_DIR=$INSTALL_DIR/include/intel
INSTALL_LIB_DIR=$INSTALL_DIR/lib

XED_RELEASE=2016-02-02

function category()
{
    printf "\n${GREEN}${1}${RESET}\n"
}

function sub_category()
{
    printf "${YELLOW}${1}${RESET}\n"
}

function notice()
{
    printf "${BLUE}${1}${RESET}\n"
}

function error()
{
    printf "${RED}${1}${RESET}\n"
    exit 1
}

# Figure out what version of XED to install.
if [[ "$OSTYPE" == "linux"* ]] ; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-lin-x86-64
elif [[ "$OSTYPE" == "darwin"* ]] ; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-mac-x86-64
else
    error "Unsupported platform: ${OSTYPE}"
    exit 1
fi;

category "Installing XED."
notice "Finding XED"
if [[ ! -e $DIR/blob/xed/${XED_VERSION}.zip ]] ; then
    error "Please download XED from ${XED_URL} and place it into ${DIR}/blob/xed/."
fi;

notice "Unpacking XED into third_party/xed"
mkdir -p $DIR/third_party/xed
rm -r $DIR/third_party/xed/*
unzip $DIR/blob/xed/${XED_VERSION}.zip -d $DIR/third_party/xed

sub_category "Installing XED into ${$INSTALL_DIR}"

notice "Installing XED headers to ${INSTALL_INCLUDE_DIR}"
sudo mkdir -p $INSTALL_INCLUDE_DIR
sudo cp -r $DIR/third_party/xed/kits/${XED_VERSION}/include/* $INSTALL_INCLUDE_DIR

notice "Installing XED libraries to ${INSTALL_LIB_DIR}"
sudo mkdir -p $INSTALL_LIB_DIR
sudo cp -r $DIR/third_party/xed/kits/${XED_VERSION}/lib/* $INSTALL_LIB_DIR

category "Installed XED"
exit 0
