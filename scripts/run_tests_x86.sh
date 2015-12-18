#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    HAS_AVX=`cat /proc/cpuinfo | grep -o 'avx ' | wc -w`

elif [[ "$OSTYPE" == "darwin"* ]]; then
	HAS_AVX=`sysctl -n machdep.cpu.features | grep -o 'AVX ' | wc -w`

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

EXIT_CODE=0

$DIR/build/run_tests_x86 || { EXIT_CODE=1 ; }
$DIR/build/run_tests_amd64 || { EXIT_CODE=1 ; }

if [[ 0 -lt $HAS_AVX ]] ; then
	$DIR/build/run_tests_x86_avx || { EXIT_CODE=1 ; }
	$DIR/build/run_tests_amd64_avx || { EXIT_CODE=1 ; }
fi

exit $EXIT_CODE
