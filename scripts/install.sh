#!/usr/bin/env bash
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

PREFIX=$1

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))


if [[ ! -e $DIR/build/cfg_to_bc ]] ; then
	$DIR/scripts/build.py
fi

mkdir -p $PREFIX/bin
mkdir -p $PREFIX/lib/mcsema2
mkdir -p $PREFIX/share/mcsema2

cp $DIR/build/cfg_to_bc $PREFIX/bin
cp $DIR/build/libOptimize.* $PREFIX/lib/mcsema2
cp $DIR/generated/sem_* $PREFIX/share/mcsema2

