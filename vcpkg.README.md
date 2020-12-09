# Remill [![Slack Chat](http://empireslacking.herokuapp.com/badge.svg)](https://empireslacking.herokuapp.com/)

<p align="center">
     <img src="docs/images/remill_logo.png" />
</p>

Remill is a static binary translator that translates machine code instructions into [LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates AArch64 (64-bit ARMv8), SPARC32 (SPARCv8), SPARC64 (SPARCv9), x86 and amd64 machine code (including AVX and AVX512) into LLVM bitcode. AArch32 (32-bit ARMv8 / ARMv7) support is underway.

Remill focuses on accurately lifting instructions. It is meant to be used as a library for other tools, e.g. [McSema](https://github.com/lifting-bits/mcsema).

## Build Status

[![Build Status](https://img.shields.io/github/workflow/status/lifting-bits/remill/CI/master)](https://github.com/lifting-bits/remill/actions?query=workflow%3ACI)

## Additional Documentation

 - [How to contribute](docs/CONTRIBUTING.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [How instructions are lifted](docs/LIFE_OF_AN_INSTRUCTION.md)
 - [The design and architecture of Remill](docs/DESIGN.md)

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#binary-lifting` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on Ubuntu 14.04, 16.04, and 18.04. Remill also works on macOS, and has experimental support for Windows.

Remill's Linux version can also be built via Docker for quicker testing.

## Dependencies

Most of Remill's dependencies can be provided by the [cxx-common](https://github.com/trailofbits/cxx-common) repository. Trail of Bits hosts downloadable, pre-built versions of cxx-common, which makes it substantially easier to get up and running with Remill. Nonetheless, the following table represents most of Remill's dependencies.

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.2+ |
| [Google Flags](https://github.com/google/glog) | Latest |
| [Google Log](https://github.com/google/glog) | Latest |
| [Google Test](https://github.com/google/googletest) | Latest |
| [LLVM](http://llvm.org/) | 3.5+ |
| [Clang](http://clang.llvm.org/) | 3.5+ |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | Latest |
| [Python](https://www.python.org/) | 2.7 |
| Unzip | Latest |
| [ccache](https://ccache.dev/) | Latest |

## Getting and Building the Code

### Vcpkg Quickstart

If you are running Ubuntu or Mac, you will be able to use pre-compiled libraries instead of building everything yourself.

First, clone the repository. This will clone the code into the `remill` directory.

```shell
git clone https://github.com/lifting-bits/remill.git
```

Next, we build Remill. This script will create another directory, `remill-build`, in the current working directory. All remaining dependencies needed by Remill will be downloaded from what was built in our CI into the `remill-build` directory. The build script will use whatever compiler is found by CMake.

```bash
./remill/scripts/build.sh
```

To run the tests you must have built Remill with `clang`:

```bash
cmake --build . --target test_dependencies
env CTEST_OUTPUT_ON_FAILURE=1 cmake --build build --target test
```

To see more options for the build script, use `--help`, open an issue, or join Slack.

### Docker Build

Ensure remill works:
```shell
# Decode some AMD64 instructions to LLVM
docker run --rm -it remill:llvm800-ubuntu18.04-amd64 \
     --arch amd64 --ir_out /dev/stdout --bytes c704ba01000000
     
# Decode some AArch64 instructions to LLVM
docker run --rm -it remill:llvm800-ubuntu18.04-amd64 \
     --arch aarch64 --address 0x400544 --ir_out /dev/stdout \
     --bytes FD7BBFA90000009000601891FD030091B7FFFF97E0031F2AFD7BC1A8C0035FD6
```
