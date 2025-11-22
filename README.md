# Remill [![Slack Chat](http://slack.empirehacking.nyc/badge.svg)](https://slack.empirehacking.nyc/)

<p align="center">
     <img src="docs/images/remill_logo.png" />
</p>

Remill is a static binary translator that translates machine code instructions into [LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates AArch64 (64-bit ARMv8), SPARC32 (SPARCv8), SPARC64 (SPARCv9), x86 and amd64 machine code (including AVX and AVX512) into LLVM bitcode. AArch32 (32-bit ARMv8 / ARMv7) support is underway.

Remill focuses on accurately lifting instructions. It is meant to be used as a library for other tools, e.g. [McSema](https://github.com/lifting-bits/mcsema).

## Build Status

[![Build Status](https://img.shields.io/github/actions/workflow/status/lifting-bits/remill/.github/workflows/build.yml)](https://github.com/lifting-bits/remill/actions/workflows/build.yml)

## Documentation

To understand how Remill works you can take a look at the following resources:

 - [Step-by-step guide on how Remill lifts an instruction](docs/LIFE_OF_AN_INSTRUCTION.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [The design and architecture of Remill](docs/DESIGN.md)

If you would like to contribute you can check out: [How to contribute](docs/CONTRIBUTING.md)

### API Documentation

Generate detailed API documentation using Doxygen:

```bash
# Install Doxygen (macOS)
brew install doxygen graphviz

# Install Doxygen (Ubuntu/Debian)
sudo apt-get install doxygen graphviz

# Generate documentation
doxygen

# Open docs/doxygen/html/index.html in your browser
```

See [docs/DOCUMENTATION.md](docs/DOCUMENTATION.md) for more details on documentation style and contributing.

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#binary-lifting` channel of the [Empire Hacking Slack](https://slack.empirehacking.nyc/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on Ubuntu 22.04. Remill also works on macOS, and has experimental support for Windows.

Remill's Linux version can also be built via Docker for quicker testing.

## Dependencies

Remill uses the following dependencies:

| Name | Version |
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [CMake](https://cmake.org/) | 3.21+ |
| [Ninja](https://ninja.build) | 1+ |
| [Google Flags](https://github.com/google/glog) | `52e94563` |
| [Google Log](https://github.com/google/glog) | v0.7.1 |
| [Google Test](https://github.com/google/googletest) | v1.17.0 |
| [LLVM](http://llvm.org/) | 15+ |
| [Clang](http://clang.llvm.org/) | 15+ |
| [Intel XED](https://github.com/intelxed/xed) | v2025.06.08 |
| [Python](https://www.python.org/) | 3+ |

## Getting and Building the Code

We will build the project using the superbuild in `dependencies/`. For more details on the dependency management system, see [Remill Dependency Management](docs/DEPENDENCIES.md).

### Clone the repository

```bash
git clone https://github.com/lifting-bits/remill
cd remill
```

### Linux/macOS

```bash
# Step 1: Build dependencies (including LLVM)
cmake -G Ninja -S dependencies -B dependencies/build
cmake --build dependencies/build

# Step 2: Build remill
cmake -G Ninja -B build -DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Windows (requires clang-cl)

**Note**: This requires running from a Visual Studio developer prompt.

```bash
# Step 1: Build dependencies
cmake -G Ninja -S dependencies -B dependencies/build -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl
cmake --build dependencies/build

# Step 2: Build remill
cmake -G Ninja -B build -DCMAKE_PREFIX_PATH:PATH=%CD%/dependencies/install -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### macOS with Homebrew LLVM:

```bash
# Install LLVM via Homebrew
brew install llvm@17
LLVM_PREFIX=$(brew --prefix llvm@17)

# Build dependencies with external LLVM
cmake -G Ninja -S dependencies -B dependencies/build -DUSE_EXTERNAL_LLVM=ON "-DCMAKE_PREFIX_PATH:PATH=$LLVM_PREFIX"
cmake --build dependencies/build

# Build remill
cmake -G Ninja -B build "-DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### Linux with system LLVM:

```bash
# Build dependencies with external LLVM
cmake -G Ninja -S dependencies -B dependencies/build -DUSE_EXTERNAL_LLVM=ON
cmake --build dependencies/build

# Build remill
cmake -G Ninja -B build "-DCMAKE_PREFIX_PATH:PATH=$(pwd)/dependencies/install" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
