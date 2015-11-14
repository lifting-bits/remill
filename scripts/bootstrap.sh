#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.


# Fetch all dependencies.
echo "${GREEN}Updating aptitude.${RESET}"
sudo apt-get update

echo "${GREEN}Downloading dependencies.${RESET}"
sudo apt-get install -y binutils-dev build-essential
sudo apt-get install -y cmake
sudo apt-get install -y libgflags-dev libgflags2
sudo apt-get install -y libgoogle-glog-dev libgoogle-glog0
sudo apt-get install -y protobuf-compiler libprotobuf-dev libprotobuf8 python-protobuf

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
RESET=`tput sgr0`

# Directory in which this script resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

# Versions of things.
LLVM_VERSION=3.7.0
PIN_VERSION=2.14-71313-gcc.4.4.7-linux


echo "${GREEN}Downloading third-party code.${RESET}"
mkdir -p $DIR/third_party

# Download LLVM.
echo "${YELLOW}Downloading LLVM ${LLVM_VERSION}.${RESET}"
wget http://llvm.org/releases/3.7.0/llvm-${LLVM_VERSION}.src.tar.xz
tar xf llvm-$LLVM_VERSION.src.tar.xz
rm llvm-$LLVM_VERSION.src.tar.xz


# Download Clang.
echo "${YELLOW}Downloading Clang ${LLVM_VERSION}.${RESET}"
wget http://llvm.org/releases/3.7.0/cfe-${LLVM_VERSION}.src.tar.xz
tar xf cfe-${LLVM_VERSION}.src.tar.xz
rm cfe-${LLVM_VERSION}.src.tar.xz


# Download PIN.
echo "${YELLOW}Downloading PIN ${PIN_VERSION}.${RESET}"
wget http://software.intel.com/sites/landingpage/pintool/downloads/pin-2.14-71313-gcc.4.4.7-linux.tar.gz
tar xf pin-${PIN_VERSION}.tar.gz
rm pin-${PIN_VERSION}.tar.gz


# Move things around.
mv llvm-$LLVM_VERSION.src $DIR/third_party/llvm
mv cfe-${LLVM_VERSION}.src $DIR/third_party/llvm/tools/clang
mv pin-${PIN_VERSION} $DIR/third_party/pin


# Compile LLVM & Clang.
echo "${GREEN}Compiling LLVM and Clang.${RESET}"
mkdir $DIR/third_party/llvm/build
cd $DIR/third_party/llvm/build

CFLAGS="-g3" CXXFLAGS="-g3" LDFLAGS="-g" \
cmake ../ \
    -DCMAKE_BUILD_TYPE:STRING=Debug \
    -DLLVM_ENABLE_RTTI:BOOL=ON \
    -DLLVM_TARGETS_TO_BUILD:STRING="X86;ARM;AArch64" \
    -DLLVM_ENABLE_ASSERTIONS:BOOL=ON \
    -DLLVM_ENABLE_THREADS:BOOL=ON
make

# Create the generated files directories.
echo "${GREEN}Creating aut-generated files.${RESET}"
cd $DIR
mkdir -p $DIR/generated
mkdir -p $DIR/generated/Arch
mkdir -p $DIR/generated/Arch/X86
mkdir -p $DIR/generated/Arch/X86/Semantics
mkdir -p $DIR/generated/CFG


# Generate 32- and 64-bit x86 machine state modules for importing by
# `cfg_to_bc`.
echo "${YELLOW}Generating architecture-specific state files.${RESET}"
cd $DIR
CXXFLAGS="-std=gnu++11 -g0 -O0 -fno-exceptions -fno-rtti -fno-asynchronous-unwind-tables -I${DIR}"
$DIR/third_party/llvm/build/bin/clang++ -x c++ -m32 -DADDRESS_SIZE_BITS=32 $CXXFLAGS -E - \
    < $DIR/mcsema/Arch/X86/Semantics/MACHINE.inc \
    > $DIR/generated/Arch/X86/Semantics/MACHINE32.cpp
    
$DIR/third_party/llvm/build/bin/clang++ -x c++ -m64 -DADDRESS_SIZE_BITS=64  $CXXFLAGS -E - \
    < $DIR/mcsema/Arch/X86/Semantics/MACHINE.inc \
    > $DIR/generated/Arch/X86/Semantics/MACHINE64.cpp

$DIR/third_party/llvm/build/bin/clang++ -g3 -m32 -DADDRESS_SIZE_BITS=32 $CXXFLAGS -emit-llvm \
    -c $DIR/generated/Arch/X86/Semantics/MACHINE32.cpp \
    -o $DIR/generated/Arch/X86/Semantics/MACHINE32.bc

$DIR/third_party/llvm/build/bin/clang++ -g3 -m64 -DADDRESS_SIZE_BITS=64 $CXXFLAGS -emit-llvm \
    -c $DIR/generated/Arch/X86/Semantics/MACHINE64.cpp \
    -o $DIR/generated/Arch/X86/Semantics/MACHINE64.bc


# Generate the protocol buffer file for the CFG definition. The lifter will
# read in CFG protobuf files and output LLVM bitcode files.
echo "${YELLOW}Generating protocol buffers.${RESET}"
cd $DIR/generated/CFG
cp $DIR/mcsema/CFG/CFG.proto $DIR/generated/CFG
protoc --cpp_out=. CFG.proto
protoc --python_out=. CFG.proto


# Build McSema. McSema will be built with the above version of Clang.
echo "${GREEN}Compiling McSema.${RESET}"
cd $DIR
mkdir $DIR/build
cd $DIR/build
cmake -G "Unix Makefiles" -DMCSEMA_DIR=$DIR ..
make all


# Find IDA.

#echo "${GREEN}Finding IDA.${RESET}"
#IDA=`locate idal64 | head -n 1`
#if [ ! -e $IDA ] ; then
#    echo "${RED}Error: Could not find IDA."
#fi


