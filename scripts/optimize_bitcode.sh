#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. Remill root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
RED=`tput setaf 1`
RESET=`tput sgr0`

if [[ -z "$1" ]] ; then
    printf "${RED}Need to specify input bitcode file as arg 1.${RESET}\n" > /dev/stderr
    exit 1
fi

if [[ "$OSTYPE" == "linux-gnu" ]] ; then
    DYLIB_SUFFIX=so

elif [[ "$OSTYPE" == "darwin"* ]] ; then
    DYLIB_SUFFIX=dylib

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n" > /dev/stderr
    exit 1
fi

BIN=`mktemp -t remill_XXXXXXXXXX`
O3_NOVEC="-O3 -fno-vectorize -fno-slp-vectorize"

$DIR/third_party/bin/opt $O3_NOVEC -o=$BIN.opt0.bc $1 || {
    printf "${RED}Could not optimize $1${RESET}\n" > /dev/stderr
    exit 1
}

$DIR/third_party/bin/opt \
    -load $DIR/build/libOptimize.$DYLIB_SUFFIX -remill_optimize \
    -o=$BIN.opt1.bc $BIN.opt0.bc || {
    printf "${RED}Could not optimize $BIN.opt0.bc${RESET}\n" > /dev/stderr
    exit 1
}

$DIR/third_party/bin/opt $O3_NOVEC -o=$BIN.opt2.bc $BIN.opt1.bc || {
    printf "${RED}Could not optimize $1.opt1.bc${RESET}\n" > /dev/stderr
    exit 1
}

$DIR/third_party/bin/opt \
    -float2int -lowerswitch -mem2reg -o=$BIN.bc $BIN.opt2.bc || {
    printf "${RED}Could not optimize $1.opt1.bc${RESET}\n" > /dev/stderr
    exit 1
}

rm $BIN.opt2.bc
rm $BIN.opt1.bc
rm $BIN.opt0.bc

printf "${BIN}.bc"
exit 0
