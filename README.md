# Remill


Remill is a static binary translator that translates machine code into [LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates x86 and amd64 machine code (including AVX and AVX512) into LLVM bitcode.

## Build Status

|       | master |
| ----- | ------ |
| Linux | [![Build Status](https://travis-ci-job-status.herokuapp.com/badge/trailofbits/remill/master/linux/)](https://travis-ci.org/trailofbits/remill) |
| macOS | [![Build Status](https://travis-ci-job-status.herokuapp.com/badge/trailofbits/remill/master/osx/)](https://travis-ci.org/trailofbits/remill) |

## Additional Documentation
 
 - [How to contribute](docs/CONTRIBUTING.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [How instructions are lifted](docs/LIFE_OF_AN_INSTRUCTION.md)
 - [How binaries are represented](docs/CFG_FORMAT.md)
 - [The design and architecture of Remill](docs/DESIGN.md)

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#tool-remill` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on Ubuntu 14.04 and 16.04.

We are actively working on porting Remill to macOS.

## Dependencies

| Name | Version | 
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.2+ |
| [Google Log](https://github.com/google/glog) | 0.3.3 |
| [Google Test](https://github.com/google/googletest) | 1.6.0 |
| [Google Protobuf](https://github.com/google/protobuf) | 2.6.1 |
| [LLVM](http://llvm.org/) | 3.9 |
| [Clang](http://clang.llvm.org/) | 3.9 |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | 2016-02-02 |
| [Python](https://www.python.org/) | 2.7 | 
| [Python Package Index](https://pypi.python.org/pypi) | Latest |
| [python-magic](https://pypi.python.org/pypi/python-magic) | Latest |
| Unzip | Latest |
| [python-protobuf](https://pypi.python.org/pypi/protobuf) | 2.6.1 |
| [Binary Ninja](https://binary.ninja) | Latest |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 6.7+ |

## Getting and Building the Code

### Step 1: Install dependencies

#### On Linux

##### Install Dependencies

```shell
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     cmake \
     libgoogle-glog-dev \
     libgtest-dev \
     libprotoc-dev libprotobuf-dev libprotobuf-dev protobuf-compiler \
     python2.7 python-pip \
     g++-multilib \
     unzip \
     software-properties-common \
     realpath

sudo pip install --upgrade pip

sudo pip install python-magic 'protobuf==2.6.1'
```

##### Using IDA on 64 bit Ubuntu

If your IDA install does not use the system's Python, you can add the `protobuf` library manually to IDA's zip of modules.

```
# Python module dir is generally in /usr/lib or /usr/local/lib
touch /path/to/python2.7/dist-packages/google/__init__.py
cd /path/to/lib/python2.7/dist-packages/              
sudo zip -rv /path/to/ida-6.X/python/lib/python27.zip google/
sudo chown your_user:your_user /home/taxicat/ida-6.7/python/lib/python27.zip
```

##### Upgrade CMake (Ubuntu 14.04)

Users wishing to run Remill on Ubuntu 14.04 should upgrade their version of CMake.

```shell
sudo add-apt-repository -y ppa:george-edison55/cmake-3.x
sudo apt-get update
sudo apt-get upgrade
sudo apt-get install cmake
```

#### On OS X

##### Install Dependencies

```
brew install glog
brew install protobuf
```

### Step 2: Clone and Enter the Repository

#### Clone the repository
```shell
git clone git@github.com:trailofbits/remill.git
```

#### Enter the repository
```shell
cd remill
```

#### Run the Build Script
```shell
./build.sh
```

### Step 3: Install the disassembler

```shell
sudo python tools/setup.py install
```

## Building and Running the Test Suite

### Build Google Test

#### On Linux

This script will build and install the Google Test framework. It will request administrator permissions.

```shell
./scripts/unix/install_gtest.sh
```

### Generate and Run the Test Cases

```shell
./scripts/x86/generate_tests.sh
./scripts/x86/run_tests.sh
```

## Try it Out

If you have a 64 bit dll, you can get started with the following commands. First, you recover control flow graph information using `remill-disass`, this can use either IDA Pro or Binary Ninja as the disassembler.

```shell
remill-disass --disassembler /path/to/ida/idal64 --arch amd64 --output target.cfg --binary libsomething.dll
```

Once you have the control flow graph information, you can lift the target binary using `remill-lift`.

```shell
remill-lift --arch_in amd64 --os_in linux --cfg target.cfg --bc_out target.bc
```

When the bitcode has been recovered by `remill-lift`, it is a good idea to optimize it using `remill-opt`.

```shell
remill-opt --bc_in target.bc --bc_out opt_target.bc
```
