#!/bin/sh

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in
  llvm35*)
    V=3.5
  ;;
  llvm36*)
    V=3.6
  ;;
  llvm37*)
    V=3.7
  ;;
  llvm38*)
    V=3.8
  ;;
  llvm39*)
    V=3.9
  ;;
  llvm4*)
    V=4
  ;;
  llvm5*)
    V=5
  ;;
  llvm6*)
    V=6
  ;;
  llvm7*)
    V=7
  ;;
  llvm8*)
    V=8
  ;;
  llvm9*)
    V=9
  ;;
  llvm10*)
    V=10
  ;;
  llvm11*)
    V=11
  ;;
  *)
    echo "Unknown LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

remill-lift-${V} "$@"
