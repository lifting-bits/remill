# Remill


Remill is a static binary translator that translates machine code into [LLVM bitcode](http://llvm.org/docs/LangRef.html). It translates x86 and amd64 machine code (including AVX and AVX512) into LLVM bitcode.

## Build Status

|       | master |
| ----- | ------ |
| Linux | [![Build Status](https://travis-ci.org/trailofbits/remill.svg?branch=master&os=linux)](https://travis-ci.org/trailofbits/remill) |

## Additional Documentation
 
 - [How to contribute](docs/CONTRIBUTING.md)
 - [How to implement the semantics of an instruction](docs/ADD_AN_INSTRUCTION.md)
 - [How instructions are lifted](docs/LIFE_OF_AN_INSTRUCTION.md)
 - [How binaries are represented](docs/CFG_FORMAT.md)
 - [The design and architecture of Remill](docs/DESIGN.md)

## Getting Help

If you are experiencing undocumented problems with Remill then ask for help in the `#tool-remill` channel of the [Empire Hacking Slack](https://empireslacking.herokuapp.com/).

## Supported Platforms

Remill is supported on Linux platforms and has been tested on Ubuntu 16.04 and openSUSE 13.2.

We are actively working on porting Remill to macOS.

## Dependencies

| Name | Version | 
| ---- | ------- |
| [Git](https://git-scm.com/) | Latest |
| [Google Log](https://github.com/google/glog) | 0.3.3 |
| [Google Test](https://github.com/google/googletest) | 1.6.0 |
| [Google Protobuf](https://github.com/google/protobuf) | 2.4.1 |
| [LLVM](http://llvm.org/) | 3.8 |
| [Clang](http://clang.llvm.org/) | 3.8 |
| [Intel XED](https://software.intel.com/en-us/articles/xed-x86-encoder-decoder-software-library) | 2016-02-02 |
| [Python](https://www.python.org/) | 2.7 | 
| [Python Package Index](https://pypi.python.org/pypi) | Latest |
| [concurrent.futures](https://pypi.python.org/pypi/futures) | Latest |
| [python-magic](https://pypi.python.org/pypi/python-magic) | Latest |
| [python-protobuf](https://pypi.python.org/pypi/protobuf) | 2.4.1 |
| [Binary Ninja](https://binary.ninja) | Latest |
| [IDA Pro](https://www.hex-rays.com/products/ida) | 6.7+ |

## Getting and Building the Code

### Step 1: Install dependencies

#### On Linux

```shell
sudo apt-get install \
    git \
    libgoogle-glog-dev \
    libgtest-dev \
    libprotoc-dev \
    libprotobuf-dev \
    llvm-3.8-dev \
    clang-3.8 \
    python2.7 \
    python-pip

sudo pip install --upgrade pip
sudo pip install \
    futures \
    python-magic \
    'protobuf==2.4.1'
```

#### On macOS (experimental)

**TODO(withzombies):** Make mac work.

### Step 2: Clone the repository

```shell
git clone git@github.com:trailofbits/remill.git
```

### Step 3: Install XED

```shell
./scripts/install_xed.sh
```

### Step 4: Create auto-generated files

```shell
./scripts/bootstrap.sh
```

### Step 4: Build the code

**TODO(pag):** Make `cmake` work.

## Try it Out

**TODO(pag):** Make `remill-lift`.
