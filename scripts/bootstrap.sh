#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. McSema root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`

LLVM_RELEASE=3.7.0
GLOG_RELEASE=v0.3.4
GFLAGS_RELEASE=v2.1.2
PROTOBUF_VERSION=protobuf-2.6.1

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    PIN_VERSION=pin-2.14-71313-gcc.4.4.7-linux
	LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-linux-gnu-ubuntu-14.04

elif [[ "$OSTYPE" == "darwin"* ]]; then
	PIN_VERSION=pin-2.14-71313-clang.5.1-mac
	LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-apple-darwin

else
    echo "${RED}Unsupported platform: ${OSTYPE}${RESET}"
    exit 1
fi

PIN_URL=http://software.intel.com/sites/landingpage/pintool/downloads/${PIN_VERSION}.tar.gz
LLVM_URL=http://llvm.org/releases/${LLVM_RELEASE}/${LLVM_VERSION}.tar.xz
GLOG_URL=https://github.com/google/glog/archive/${GLOG_RELEASE}.tar.gz
GFLAGS_URL=https://github.com/gflags/gflags/archive/${GFLAGS_RELEASE}.tar.gz
PROTOBUF_URL=https://github.com/google/protobuf/releases/download/v2.6.1/${PROTOBUF_VERSION}.tar.gz

function download_and_install_llvm()
{
	echo "${YELLOW}Downloading LLVM and clang ${LLVM_VERSION}.${RESET}"

	# Create third_party directory if it doesn't exist
	mkdir -p $DIR/third_party
	pushd $DIR/third_party

	# Download a pre-built clang+llvm to it. OS X doesn't have wget by default. :(
	curl -O ${LLVM_URL}

	# Extract it to the path expected by compile_semantics.sh
	mkdir -p $DIR/third_party/src/llvm/
	tar xf ${LLVM_VERSION}.tar.xz -C $DIR/third_party --strip-components=1
	rm ${LLVM_VERSION}.tar.xz
	popd
}

function download_and_install_gflags()
{
	echo "${YELLOW}Downloading and installing gflags.${RESET}"

	pushd $DIR/third_party
	curl -L -O ${GFLAGS_URL}
	mkdir -p $DIR/third_party/src/gflags
	tar xf ${GFLAGS_RELEASE}.tar.gz -C src/gflags/ --strip-components=1
	rm ${GFLAGS_RELEASE}.tar.gz
	popd

	pushd $DIR/third_party/src/gflags
	mkdir build
	cd build
	cmake \
		-G "Unix Makefiles" \
		-DCMAKE_INSTALL_PREFIX:STRING=$DIR/third_party \
		-DGFLAGS_NAMESPACE:STRING=google \
		..
	make
	make install
	popd
}

function download_and_install_glog()
{
	echo "${YELLOW}Downloading and installing glog.${RESET}"

	pushd $DIR/third_party

	curl -L -O https://github.com/google/glog/archive/${GLOG_RELEASE}.tar.gz
	mkdir -p $DIR/third_party/src/glog
	tar xf ${GLOG_RELEASE}.tar.gz -C src/glog/ --strip-components=1
	rm ${GLOG_RELEASE}.tar.gz
	popd

	pushd $DIR/third_party/src/glog
	./configure \
		--prefix=$DIR/third_party \
		--disable-rtti \
		--enable-static \
		--disable-shared
	make
	make install
	popd
}

function download_and_install_protobuf()
{
	echo "${YELLOW}Downloading and installing protobuf.${RESET}"

	pushd $DIR/third_party
	curl -L -O ${PROTOBUF_URL}
	mkdir -p $DIR/third_party/src/protobuf
	tar xf ${PROTOBUF_VERSION}.tar.gz -C src/protobuf/ --strip-components=1
	rm ${PROTOBUF_VERSION}.tar.gz
	popd

	pushd $DIR/third_party/src/protobuf
	./configure \
		--prefix=$DIR/third_party
	make
	make install
	popd
}


function download_and_extract_pin()
{
	echo "${YELLOW}Downloading and installing pin.${RESET}"

	pushd $DIR/third_party
	curl -L -O ${PIN_URL}
	mkdir -p $DIR/third_party/src/pin
	tar xf ${PIN_VERSION}.tar.gz -C src/pin/ --strip-components=1
	rm ${PIN_VERSION}.tar.gz
	popd

	# 'install' XED.
	mkdir -p $DIR/third_party/include/intel
	cp -r $DIR/third_party/src/pin/extras/xed-intel64/lib/* $DIR/third_party/lib
	cp -r $DIR/third_party/src/pin/extras/xed-intel64/include/* $DIR/third_party/include/intel
	cp -r $DIR/third_party/src/pin/extras/xed-intel64/bin/* $DIR/third_party/bin
}

# Fetch all dependencies.
echo "${GREEN}Checking dependencies.${RESET}"

mkdir -p $DIR/third_party
mkdir -p $DIR/third_party/bin
mkdir -p $DIR/third_party/lib
mkdir -p $DIR/third_party/include
mkdir -p $DIR/third_party/src
mkdir -p $DIR/third_party/share

if [[ -e $DIR/third_party/bin/clang ]]; then
	echo "${BLUE}LLVM and clang FOUND!${RESET}"
else
	download_and_install_llvm
fi;

export CC="${DIR}/third_party/bin/clang"
export CXX="${DIR}/third_party/bin/clang++"

export CFLAGS="-isystem ${DIR}/third_party/include -g3"
export CXXFLAGS="-isystem ${DIR}/third_party/include -g3"
export LDFLAGS="-g"

if [[ -e $DIR/third_party/lib/libgflags.a ]]; then
	echo "${BLUE}gflags FOUND!${RESET}"
else
	download_and_install_gflags
fi;

if [[ -e $DIR/third_party/lib/libglog.a ]]; then
	echo "${BLUE}glog FOUND!${RESET}"
else
	download_and_install_glog
fi;

if [[ -e $DIR/third_party/bin/protoc ]]; then
	echo "${BLUE}protobuf FOUND!${RESET}"
else
	download_and_install_protobuf
fi;

if [[ -e $DIR/third_party/bin/xed ]]; then
	echo "${BLUE}pin FOUND!${RESET}"
else
	download_and_extract_pin
fi;

# Create the generated files directories.
echo "${GREEN}Auto-generating files.${RESET}"
cd $DIR
mkdir -p $DIR/generated
mkdir -p $DIR/generated/Arch
mkdir -p $DIR/generated/CFG

# Generate 32- and 64-bit x86 machine state modules for importing by
# `cfg_to_bc`.
echo "${YELLOW}Generating architecture-specific state files.${RESET}"
$DIR/scripts/compile_semantics.sh

# Generate the protocol buffer file for the CFG definition. The lifter will
# read in CFG protobuf files and output LLVM bitcode files.
echo "${YELLOW}Generating protocol buffers.${RESET}"
cd $DIR/generated/CFG
cp $DIR/mcsema/CFG/CFG.proto $DIR/generated/CFG
$DIR/third_party/bin/protoc --cpp_out=. CFG.proto
$DIR/third_party/bin/protoc --python_out=. CFG.proto

# Build McSema. McSema will be built with the above version of Clang.
echo "${GREEN}Compiling McSema.${RESET}"
cd $DIR
mkdir -p $DIR/build
cd $DIR/build
cmake \
	-G "Unix Makefiles" \
	-DMCSEMA_DIR:STRING=$DIR \
	-DCMAKE_PREFIX_PATH:STRING=$DIR/third_party \
	..

make all
