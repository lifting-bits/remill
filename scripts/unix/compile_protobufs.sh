#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

DIR=$(dirname $(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`

function category()
{
    printf "\n${GREEN}${1}${RESET}\n"
}

function sub_category()
{
    printf "${YELLOW}${1}${RESET}\n"
}

function notice()
{
    printf "${BLUE}${1}${RESET}\n"
}

function error()
{
    printf "${RED}${1}${RESET}\n"
    exit 1
}

# Generate the protocol buffer file for the CFG definition. The lifter will
# read in CFG protobuf files and output LLVM bitcode files.
sub_category "Generating protocol buffers."
cd $DIR/generated/CFG
cp $DIR/remill/CFG/CFG.proto $DIR/generated/CFG

protoc --cpp_out=. CFG.proto
protoc --python_out=. CFG.proto

sub_category "Generating test save state code."
$DIR/scripts/print_x86_save_state_asm.sh

popd