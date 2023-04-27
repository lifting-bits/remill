#!/bin/sh

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in
  llvm15*)
    V=15
  ;;
  llvm16*)
    V=16
  ;;
  *)
    echo "Unknown LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

remill-lift-${V} "$@"
