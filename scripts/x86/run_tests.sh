#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    HAS_AVX=`cat /proc/cpuinfo | grep -o 'avx ' | wc -w`

elif [[ "$OSTYPE" == "darwin"* ]]; then
    HAS_AVX=`sysctl -n machdep.cpu.features | grep -o 'AVX ' | wc -w`
    echo "Skipping running tests since we're on a Mac"
    exit 0

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

EXIT_CODE=0

$DIR/generated/Arch/X86/Tests/x86 --minloglevel 1 || { EXIT_CODE=1 ; }
$DIR/generated/Arch/X86/Tests/amd64 --minloglevel 1 || { EXIT_CODE=1 ; }

if [[ 0 -lt $HAS_AVX ]] ; then
    $DIR/generated/Arch/X86/Tests/x86_avx --minloglevel 1 || { EXIT_CODE=1 ; }
    $DIR/generated/Arch/X86/Tests/amd64_avx --minloglevel 1 || { EXIT_CODE=1 ; }
fi

exit $EXIT_CODE
