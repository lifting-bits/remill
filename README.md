# Remill

Remill is a static binary translator that translates machine code instructions into [LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates x86 and amd64 machine code (including AVX and AVX512) into LLVM bitcode. AArch64 support is underway.

Remill focuses on accurately lifting instructions. It is meant to be used as a library for other tools, e.g. [McSema](https://github.com/trailofbits/mcsema).

## Build Status

|       | master |
| ----- | ------ |
| Linux | [![Build Status](https://travis-ci-job-status.herokuapp.com/badge/trailofbits/remill/master/linux/)](https://travis-ci.org/trailofbits/remill) |

## Additional Documentation
 
 - [How to contribute](docs/CONTRIBUTING.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [How instructions are lifted](docs/LIFE_OF_AN_INSTRUCTION.md)
 - [The design and architecture of Remill](docs/DESIGN.md)

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on Ubuntu 14.04 and 16.04.

We are actively working on porting Remill to macOS.

## Dependencies

Most of Remill's dependencies can be provided by the [cxx-common](https://github.com/trailofbits/cxx-common) repository. Trail of Bits hosts downloadable, pre-built versions of cxx-common, which makes it substantially easier to get up and running with Remill. Nonetheless, the following table represents most of Remill's dependencies.

| Name | Version | 
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.2+ |
| [Google Flags](https://github.com/google/glog) | 2.2.0 |
| [Google Log](https://github.com/google/glog) | 0.3.4 |
| [Google Test](https://github.com/google/googletest) | 1.8.0 |
| [LLVM](http://llvm.org/) | 3.5+ |
| [Clang](http://clang.llvm.org/) | 3.5+ |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | 2016-02-02 |
| [Python](https://www.python.org/) | 2.7 | 
| Unzip | Latest |

## Getting and Building the Code

### On Linux

First, update aptitude and get install the baseline dependencies.

```shell
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install \
     git \
     python-pip \
     build-essential \
     realpath
```

Next, clone the repository. This will clone the code into the `remill` directory.

```shell
git clone git@github.com:trailofbits/remill.git
```

Finally, build remill. This script will create another directory, `remill-build`
at the same level as the `remill` directory. All remaining dependencies needed
by Remill will be built in the `remill-build` directory.

```shell
./remill/scripts/build.sh
```



### On OS X

##### Install Dependencies

```
brew install glog
```

### Step 2: Clone and Enter the Repository

#### Clone the repository



#### Build the code.



## Building and Running the Test Suite

### Build Google Test

#### On Linux

This script will build and install the Google Test framework. It will request administrator permissions.

```shell
./scripts/unix/install_gtest.sh
```

### Generate and Run the Test Cases

```shell
make build_x86_tests
ctest
```

## Try it Out

Remill is a library, and so there is no single way to try it. However, you can head on over to the [McSema](https://github.com/trailofbits/mcsema) repository and try that!
