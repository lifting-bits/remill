#!/bin/sh

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in
  llvm3.5)
    V=3.5
  ;;
  llvm3.6)
    V=3.6
  ;;
  llvm3.7)
    V=3.7
  ;;
  llvm3.8)
    V=3.8
  ;;
  llvm3.9)
    V=3.9
  ;;
  # There is an llvm401 that we treat as 4.0
  llvm4)
    V=4
  ;;
  llvm5)
    V=5
  ;;
  llvm6)
    V=6
  ;;
  llvm7)
    V=7
  ;;
  llvm8)
    V=8
  ;;
  llvm9)
    V=9
  ;;
  llvm10)
    V=10
  ;;
  llvm11)
    V=11
  ;;
  *)
    echo "Unknown LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

remill-lift-${V} "$@"
