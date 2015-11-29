#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    exec $SCRIPTS_DIR/bootstrap_linux.sh

elif [[ "$OSTYPE" == "darwin"* ]]; then
	exec $SCRIPTS_DIR/bootstrap_osx.sh

else
    echo "Unsupported platform: $OSTYPE"
fi
