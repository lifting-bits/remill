#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. Remill root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`


function fix_library()
{
    if [[ "$OSTYPE" == "darwin"* ]] ; then
        install_name_tool -id $DIR/third_party/lib/lib$1.dylib $DIR/third_party/lib/lib$1.dylib
    fi;
}

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

function create_directory_tree()
{
    mkdir -p $DIR/third_party
    mkdir -p $DIR/generated
    mkdir -p $DIR/generated/Arch
    mkdir -p $DIR/generated/CFG
    touch $DIR/generated/__init__.py
    touch $DIR/generated/CFG/__init__.py
}


function generate_files()
{
    # Create the generated files directories.
    category "Auto-generating files."
    pushd $DIR
    
    # Generate 32- and 64-bit x86 machine state modules for importing by
    # `cfg_to_bc`.
    sub_category "Generating architecture-specific state files."
    $DIR/scripts/compile_semantics.sh || {
        error "Error compiling instruction semantics."
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
}

create_directory_tree
generate_files
