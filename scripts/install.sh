#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
RESET=`tput sgr0`

PREFIX=$1
if [[ -z "${PREFIX}" ]] ; then
	printf "${RED}ERROR! Specify install prefix with first argument.${RESET}\n"
	exit 1
fi

if [[ ! -e $DIR/build/cfg_to_bc ]] ; then
	$DIR/scripts/build.py
fi

mkdir -p $PREFIX/bin
mkdir -p $PREFIX/include
mkdir -p $PREFIX/lib/remill
mkdir -p $PREFIX/share/remill

cp $DIR/build/cfg_to_bc $PREFIX/bin
cp $DIR/build/libOptimize.* $PREFIX/lib/remill
cp $DIR/generated/sem_* $PREFIX/share/remill

