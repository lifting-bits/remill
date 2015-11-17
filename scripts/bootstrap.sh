#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    exec $SCRIPTS_DIR/bootstrap_linux.sh

elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "Mac OS X isn't yet supported! You should add it ;-)"

else
    echo "Unsupported platform: $OSTYPE"
fi
