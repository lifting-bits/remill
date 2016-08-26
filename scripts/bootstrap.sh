#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

# Directory in which the script dir resides (i.e. Remill root dir).
DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
RESET=`tput sgr0`


GLOG_RELEASE=v0.3.4
GFLAGS_RELEASE=v2.1.2
PROTOBUF_VERSION=2.5.0
PROTOBUF_RELEASE=protobuf-${PROTOBUF_VERSION}
GTEST_RELEASE=release-1.7.0
XED_RELEASE=2016-02-02

LLVM_RELEASE=3.8.0
LLVM_RELEASE_DIR=releases/${LLVM_RELEASE}

if [[ "$OSTYPE" == "linux-gnu" ]]; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-lin-x86-64
    LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-linux-gnu-ubuntu-14.04
    REMILL_OS_NAME="linux"
    LIB_EXT=so
    STDLIB="libstdc++"
    LIB_LINK_FLAGS=

elif [[ "$OSTYPE" == "darwin"* ]]; then
    XED_VERSION=xed-install-base-${XED_RELEASE}-mac-x86-64
    LLVM_RELEASE=3.8.0
    LLVM_VERSION=clang+llvm-${LLVM_RELEASE}-x86_64-apple-darwin
    REMILL_OS_NAME="mac"
    LIB_EXT=dylib
    STDLIB="libc++"
    LIB_LINK_FLAGS="-lc++ -lc++abi"

else
    printf "${RED}Unsupported platform: ${OSTYPE}${RESET}\n"
    exit 1
fi

XED_URL=https://software.intel.com/system/files/managed/58/cc/${XED_VERSION}.zip
LLVM_URL=http://llvm.org/${LLVM_RELEASE_DIR}/${LLVM_VERSION}.tar.xz
GLOG_URL=https://github.com/google/glog/archive/${GLOG_RELEASE}.tar.gz
GFLAGS_URL=https://github.com/gflags/gflags/archive/${GFLAGS_RELEASE}.tar.gz
PROTOBUF_URL=https://github.com/google/protobuf/releases/download/v${PROTOBUF_VERSION}/${PROTOBUF_RELEASE}.tar.gz
GTEST_URL=https://github.com/google/googletest/archive/${GTEST_RELEASE}.tar.gz

function fix_library()
{
    if [[ "$OSTYPE" == "darwin"* ]]; then
        install_name_tool -id $DIR/third_party/lib/lib$1.dylib $DIR/third_party/lib/lib$1.dylib
    fi
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
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=OFF \
        ..
    make
    make install
    fix_library gflags
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
        --disable-static \
        --enable-shared \
        --disable-rtti
    make
    make install
    fix_library glog
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

    CXXFLAGS="${CXXFLAGS} -DGOOGLE_PROTOBUF_NO_RTTI"
    ./configure \
        --prefix=$DIR/third_party
    make
    make install
    fix_library protobuf
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
        -DBUILD_SHARED_LIBS=ON \
        -DBUILD_STATIC_LIBS=OFF \
        ..
    make
    cp $DIR/third_party/src/googletest/build/libgtest.$LIB_EXT $DIR/third_party/lib
    cp -r $DIR/third_party/src/googletest/include/gtest $DIR/third_party/include
    fix_library gtest
    popd
}

function download_and_extract_xed()
{
    sub_category "Downloading and installing XED."

    if [[ ! -e $DIR/blob/xed/${XED_VERSION}.zip ]] ; then
        error "Please download XED from ${XED_URL} and place it into ${DIR}/blob/xed/."
    fi

    mkdir -p $DIR/third_party/src/xed
    unzip $DIR/blob/xed/${XED_VERSION}.zip -d $DIR/third_party/src/xed

    # 'install' XED.
    mkdir -p $DIR/third_party/include/intel
    cp -r $DIR/third_party/src/xed/kits/${XED_VERSION}/lib/* $DIR/third_party/lib
    cp -r $DIR/third_party/src/xed/kits/${XED_VERSION}/include/* $DIR/third_party/include/intel
    fix_library xed
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
    
    export CFLAGS="-isystem ${DIR}/third_party/include -g3 -fno-omit-frame-pointer -fPIC"
    export CXXFLAGS="-isystem ${DIR}/third_party/include -g3 -fno-omit-frame-pointer -fPIC -fno-rtti -fno-exceptions -stdlib=${STDLIB}"
    export LDFLAGS="-g ${LIB_LINK_FLAGS}"
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

    if [[ -e $DIR/third_party/lib/libgflags.$LIB_EXT ]]; then
        notice "gflags FOUND!"
    else
        download_and_install_gflags
    fi;
    
    if [[ -e $DIR/third_party/lib/libglog.$LIB_EXT ]]; then
        notice "${BLUE}glog FOUND!"
    else
        download_and_install_glog
    fi;
    
    if [[ -e $DIR/third_party/bin/protoc ]]; then
        notice "${BLUE}protobuf FOUND!"
    else
        download_and_install_protobuf
    fi;
    
    if [[ -e $DIR/third_party/lib/libgtest.$LIB_EXT ]]; then
        notice "${BLUE}googletest FOUND!"
    else
        download_and_install_gtest
    fi;
    
    if [[ -e $DIR/third_party/lib/libxed.$LIB_EXT ]] ; then
        notice "${BLUE}XED FOUND!"
    else
        download_and_extract_xed
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
    cp $DIR/remill/CFG/CFG.proto $DIR/generated/CFG
    $DIR/third_party/bin/protoc --cpp_out=. CFG.proto
    $DIR/third_party/bin/protoc --python_out=. CFG.proto
    
    sub_category "Generating test save state code."
    $DIR/scripts/print_x86_save_state_asm.sh

    popd
}

function build_remill()
{
    category "Compiling Remill"
    python $DIR/scripts/build.py --debug --num_workers 1 --stop_on_error
}

create_directory_tree
download_dependencies
generate_files
build_remill
