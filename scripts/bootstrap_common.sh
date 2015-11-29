#!/usr/bin/env bash
# Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved.

function download_and_install_llvm()
{
	echo "${YELLOW}Downloading LLVM and clang ${LLVM_VERSION}.${RESET}"

	# Create third_party directory if it doesn't exist
	mkdir -p $DIR/third_party
	pushd $DIR/third_party

	# Download a pre-built clang+llvm to it. OS X doesn't have wget by default. :(
	curl -O ${LLVM_URL}

	# Extract it to the path expected by compile_semantics.sh
	mkdir -p $DIR/third_party/llvm/build
	tar xf clang+llvm-${LLVM_VERSION}-x86_64-apple-darwin.tar.xz -C llvm/build/ --strip-components=1

	popd
}

function download_and_install_glog()
{
	echo "${YELLOW}Downloading and installing glog.${RESET}"

	pushd $DIR/third_party

	#git clone https://github.com/google/glog.git -t v0.3.4
	curl -L -O https://github.com/google/glog/archive/v0.3.4.tar.gz

	mkdir -p $DIR/third_party/glog
	tar xf v0.3.4.tar.gz -C glog/ --strip-components=1

	popd

	pushd $DIR/third_party/glog
	./configure --prefix=/usr/local
	make
	make install
	popd

}

function download_and_extract_pin()
{
	echo "${YELLOW}Downloading and installing pin.${RESET}"

	pushd $DIR/third_party

	curl -L -O ${PIN_URL}

	mkdir -p $DIR/third_party/pin
	tar zxf pin-${PIN_VERSION}.tar.gz -C pin/ --strip-components=1

	popd
}

# Fetch all dependencies.
echo "${GREEN}Checking dependencies.${RESET}"

# Check for llvm ${LLVM_VERSION}
if [[ -e $DIR/third_party/llvm/build/bin/clang++ ]]; then
	echo "${GREEN}LLVM and clang FOUND!${RESET}"
else
	download_and_install_llvm
fi;

if [[ -e /usr/local/include/glog ]]; then
	echo "${GREEN}glog FOUND!${RESET}"
else
	download_and_install_glog
fi;


if [[ -e $DIR/third_party/pin/pin ]]; then
	echo "${GREEN}pin FOUND!${RESET}"
else
	download_and_extract_pin
fi;

# Create the generated files directories.
echo "${GREEN}Creating aut-generated files.${RESET}"
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
protoc --cpp_out=. CFG.proto
protoc --python_out=. CFG.proto


# Build McSema. McSema will be built with the above version of Clang.
echo "${GREEN}Compiling McSema.${RESET}"
cd $DIR
mkdir -p $DIR/build
cd $DIR/build
cmake -G "Unix Makefiles" -DMCSEMA_DIR=$DIR -DCMAKE_PREFIX_PATH=$DIR/third_party/llvm/build/share/llvm ..
make all