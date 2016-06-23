#!/usr/bin/env bash

# Directory in which this script resides (i.e. Remill scripts dir).
SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
REMILL_DIR=$(dirname ${SCRIPTS_DIR})

RED=`tput setaf 1`
RESET=`tput sgr0`

if [[ -z "$1" ]] ; then
	printf "${RED}Please specify input binary as arg 1.${RESET}\n" > /dev/stderr
	exit 1
fi

# Find IDA
if [[ "$OSTYPE" == "linux-gnu" ]]; then
	IDA=`locate idal64 | head -n 1`

elif [[ "$OSTYPE" == "darwin"* ]]; then
	IDA="/Applications/IDA Pro 6.9/IDA binaries/idal64"
	if [[ ! -e $IDA ]] ; then
		IDA="/Applications/IDA Pro 6.8/IDA binaries/idal64"
	fi
	if [[ ! -e $IDA ]] ; then
		IDA="/Applications/IDA Pro 6.7/IDA binaries/idal64"
	fi
fi

BIN=`mktemp -t remill2_XXXXXXXXXX`

if [[ ! -e $IDA ]] ; then
	printf "${RED}Could not find IDA.${RESET}\n" > /dev/stderr
	exit 1
fi

cp $1 $BIN

export PYTHONPATH=${REMILL_DIR}:${PYTHONPATH}
export TVHEADLESS=1

"$IDA" -B -S"${SCRIPTS_DIR}/ida_get_cfg.py --output=${BIN}.cfg" $BIN &> /dev/null || {
    printf "Unable to lift CFG\n" > /dev/stderr
    rm $BIN
    exit 1
}

rm $BIN
printf "${BIN}.cfg"
exit 0
