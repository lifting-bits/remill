#!/usr/bin/env bash

# Directory in which this script resides (i.e. McSema scripts dir).
SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MCSEMA_DIR=$(dirname ${SCRIPTS_DIR})

# Find IDA
if [[ "$OSTYPE" == "linux-gnu" ]]; then
	IDA=`locate idal64 | head -n 1`
	BIN=`mktemp --tmpdir=/tmp mcsema2_XXXXXXXXXX`
elif [[ "$OSTYPE" == "darwin"* ]]; then
	IDA="/Applications/IDA Pro 6.8/IDA binaries/idal64"
	BIN=`mktemp -t mcsema2_XXXXXXXXXX`
fi

cp $1 $BIN

export PYTHONPATH=${MCSEMA_DIR}:${PYTHONPATH}
export TVHEADLESS=1

"$IDA" -B -S"${SCRIPTS_DIR}/ida_get_cfg.py --output=${BIN}.cfg" $BIN &> /dev/null || {
    printf "Unable to lift CFG\n" > /dev/stderr
    rm $BIN
    exit 1
}

rm $BIN
printf "${BIN}.cfg\n"
exit 0
