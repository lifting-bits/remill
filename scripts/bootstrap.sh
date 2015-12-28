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
PROTOBUF_VERSION=2.5.0
PROTOBUF_RELEASE=protobuf-${PROTOBUF_VERSION}
GTEST_RELEASE=release-1.7.0

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    PIN_VERSION=pin-2.14-71313-gcc.4.4.7-linux
	LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-linux-gnu-ubuntu-14.04
    MCSEMA_OS_NAME="linux"

elif [[ "$OSTYPE" == "darwin"* ]]; then
	PIN_VERSION=pin-2.14-71313-clang.5.1-mac
	LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-apple-darwin
    MCSEMA_OS_NAME="mac"

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

PIN_URL=http://software.intel.com/sites/landingpage/pintool/downloads/${PIN_VERSION}.tar.gz
LLVM_URL=http://llvm.org/releases/${LLVM_RELEASE}/${LLVM_VERSION}.tar.xz
GLOG_URL=https://github.com/google/glog/archive/${GLOG_RELEASE}.tar.gz
GFLAGS_URL=https://github.com/gflags/gflags/archive/${GFLAGS_RELEASE}.tar.gz
PROTOBUF_URL=https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOBUF_RELEASE}.tar.gz
GTEST_URL=https://github.com/google/googletest/archive/${GTEST_RELEASE}.tar.gz

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

function download_and_install_llvm()
{
	sub_category "Downloading LLVM and clang ${LLVM_VERSION}."

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
	sub_category "Downloading and installing gflags."

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
	sub_category "Downloading and installing glog."

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
	sub_category "Downloading and installing protobuf."

	pushd $DIR/third_party
	curl -L -O ${PROTOBUF_URL}
	mkdir -p $DIR/third_party/src/protobuf
	tar xf ${PROTOBUF_RELEASE}.tar.gz -C src/protobuf/ --strip-components=1
	rm ${PROTOBUF_RELEASE}.tar.gz
	popd

	pushd $DIR/third_party/src/protobuf
	./configure \
		--prefix=$DIR/third_party
	make
	make install
	popd
}

function download_and_install_gtest()
{
    sub_category "Downloading and installing googletest."
    pushd $DIR/third_party
    curl -L -O ${GTEST_URL}
    mkdir -p $DIR/third_party/src/googletest
    tar xf ${GTEST_RELEASE}.tar.gz -C src/googletest/ --strip-components=1
    rm ${GTEST_RELEASE}.tar.gz
    popd
    
    pushd $DIR/third_party/src/googletest
    mkdir build
    cd build
    cmake \
        -G "Unix Makefiles" \
        -DCMAKE_INSTALL_PREFIX:STRING=$DIR/third_party \
        -DGTEST_HAS_PTHREAD=0 \
        -DGTEST_CREATE_SHARED_LIBRARY=0 \
        ..
    make
    cp $DIR/third_party/src/googletest/build/libgtest.a $DIR/third_party/lib
    cp -r $DIR/third_party/src/googletest/include/gtest $DIR/third_party/include
    popd
}

function download_and_extract_pin()
{
	sub_category "Downloading and installing pin."

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

function create_directory_tree()
{
    mkdir -p $DIR/third_party
    mkdir -p $DIR/third_party/bin
    mkdir -p $DIR/third_party/lib
    mkdir -p $DIR/third_party/include
    mkdir -p $DIR/third_party/src
    mkdir -p $DIR/third_party/share
    
    mkdir -p $DIR/generated
    mkdir -p $DIR/generated/Arch
    mkdir -p $DIR/generated/CFG
    
    touch $DIR/generated/__init__.py
    touch $DIR/generated/CFG/__init__.py
}

function change_compiler_to_llvm()
{
    export CC="${DIR}/third_party/bin/clang"
    export CXX="${DIR}/third_party/bin/clang++"
    
    export CFLAGS="-isystem ${DIR}/third_party/include -g3"
    export CXXFLAGS="-isystem ${DIR}/third_party/include -g3"
    export LDFLAGS="-g"
}

function download_dependencies()
{
    category "Checking dependencies."
    
    if [[ -e $DIR/third_party/bin/clang ]]; then
        notice "LLVM and clang FOUND!"
	else
	    download_and_install_llvm
	fi;
	
	change_compiler_to_llvm

    if [[ -e $DIR/third_party/lib/libgflags.a ]]; then
        notice "gflags FOUND!"
	else
	    download_and_install_gflags
	fi;
	
	if [[ -e $DIR/third_party/lib/libglog.a ]]; then
	    notice "${BLUE}glog FOUND!"
	else
	    download_and_install_glog
	fi;
	
	if [[ -e $DIR/third_party/bin/protoc ]]; then
	    notice "${BLUE}protobuf FOUND!"
	else
	    download_and_install_protobuf
	fi;
	
	if [[ -e $DIR/third_party/lib/libgtest.a ]]; then
	    notice "${BLUE}googletest FOUND!"
	else
	    download_and_install_gtest
	fi;
	
	if [[ -e $DIR/third_party/bin/xed ]]; then
	    notice "${BLUE}pin FOUND!"
	else
	    download_and_extract_pin
	fi;
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
	cp $DIR/mcsema/CFG/CFG.proto $DIR/generated/CFG
	$DIR/third_party/bin/protoc --cpp_out=. CFG.proto
	$DIR/third_party/bin/protoc --python_out=. CFG.proto
	
	popd
}

function build_mcsema()
{
    category "Compiling McSema."
	pushd $DIR
	mkdir -p $DIR/build
	pushd $DIR/build
	cmake \
	    -G "Unix Makefiles" \
	    -DMCSEMA_DIR:STRING=$DIR \
	    -DMCSEMA_OS_NAME:STRING=$MCSEMA_OS_NAME \
	    -DCMAKE_PREFIX_PATH:STRING=$DIR/third_party \
	    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
	    ..
	make all
	popd
	popd
}

create_directory_tree
download_dependencies
generate_files
build_mcsema
