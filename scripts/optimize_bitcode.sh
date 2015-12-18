#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
RED=`tput setaf 1`
RESET=`tput sgr0`

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    DYLIB_SUFFIX=so

elif [[ "$OSTYPE" == "darwin"* ]]; then
    DYLIB_SUFFIX=dylib

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

$DIR/third_party/bin/opt -O3 -o=$1.opt0.bc $1 || {
	printf "${RED}Could not optimize $1${RESET}\n"
	exit 1
}

$DIR/third_party/bin/opt \
	-load $DIR/build/libOptimizer.$DYLIB_SUFFIX -deferred_inliner \
	-o=$1.opt1.bc $1.opt0.bc || {
	printf "${RED}Could not optimize $1.opt0.bc${RESET}\n"
	exit 1
}

$DIR/third_party/bin/opt -O3 -o=$1.opt2.bc $1.opt1.bc || {
	printf "${RED}Could not optimize $1.opt1.bc${RESET}\n"
	exit 1
}

mv $1.opt2.bc $2
rm $1.opt1.bc
rm $1.opt0.bc

exit 0
