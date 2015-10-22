#!/usr/bin/env bash

# Directory in which this script resides (i.e. McSema scripts dir).
SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
IDA=`locate idal64`
BIN=`mktemp`
cp $1 $BIN
$IDA -B -S"${SCRIPTS_DIR}/ida_get_cfg.py --output=${BIN}.cfg" $BIN
echo "Saved CFG to ${BIN}.cfg"
