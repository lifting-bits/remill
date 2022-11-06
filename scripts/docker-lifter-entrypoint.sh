#!/bin/sh

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in
  llvm14*)
    V=14
  ;;
  llvm15*)
    V=15
  ;;
  *)
    echo "Unknown LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

remill-lift-${V} "$@"
