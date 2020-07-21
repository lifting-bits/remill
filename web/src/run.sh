#!/usr/bin/env bash
set -e
REPO=`git rev-parse --show-toplevel`
docker build -t remill/web $REPO/web/src
docker run \
    --rm \
    -u $(id -u):$(id -g) \
    -e CCACHE_DIR="$REPO/web/build/cache" \
    -v "$REPO:$REPO" \
    -w "`pwd`" \
    remill/web \
    "$@"