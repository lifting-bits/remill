#!/usr/bin/env bash

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

$DIR/third_party/bin/opt \
    -load $DIR/build/libFinalize.$DYLIB_SUFFIX \
    -remill_finalize \
    -o=$BIN.bc $1 || {
    printf "${RED}Could not finalize $1${RESET}\n" > /dev/stderr
    exit 1
}

printf "${BIN}.bc"
exit 0
