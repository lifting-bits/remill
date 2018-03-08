#!/usr/bin/env bash
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# General directory structure:
#   /path/to/home/remill
#   /path/to/home/remill-build

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
SRC_DIR=$( cd "$( dirname "${SCRIPTS_DIR}" )" && pwd )
CURR_DIR=$( pwd )
BUILD_DIR=${CURR_DIR}/remill-build
INSTALL_DIR=/usr/local
LLVM_VERSION=llvm40
OS_VERSION=
ARCH_VERSION=

# There are pre-build versions of various libraries for specific
# Ubuntu releases.
function GetUbuntuOSVersion
{
  # Version name of OS (e.g. xenial, trusty).
  source /etc/lsb-release

  case "${DISTRIB_CODENAME}" in
    xenial)
      OS_VERSION=ubuntu1604
      return 0
    ;;
    trusty)
      OS_VERSION=ubuntu1404
      return 0
    ;;
    *)
      printf "[x] Ubuntu ${DISTRIB_CODENAME} is not supported. Only xenial (16.04) and trusty (14.04) are supported.\n"
      return 1
    ;;
  esac
}

# Figure out the architecture of the current machine.
function GetArchVersion
{
  local version=$( uname -m )

  case "${version}" in
    x86_64)
      ARCH_VERSION=amd64
      return 0
    ;;
    x86-64)
      ARCH_VERSION=amd64
      return 0
    ;;
    aarch64)
      ARCH_VERSION=aarch64
      return 0
    ;;
    *)
      printf "[x] ${version} architecture is not supported. Only aarch64 and x86_64 (i.e. amd64) are supported.\n"
      return 1
    ;;
  esac
}

function DownloadCxxCommon
{
  curl -O https://s3.amazonaws.com/cxx-common/${LIBRARY_VERSION}.tar.gz
  if [[ $? -ne 0 ]]; then
    return 1
  fi
  
  local TAR_OPTIONS="--warning=no-timestamp"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    TAR_OPTIONS=""
  fi

  tar xf ${LIBRARY_VERSION}.tar.gz $TAR_OPTIONS
  rm ${LIBRARY_VERSION}.tar.gz

  # Make sure modification times are not in the future.
  find ${BUILD_DIR}/libraries -type f -exec touch {} \;
  
  return 0
}

# Attempt to detect the OS distribution name.
function GetOSVersion
{
  local distribution_name=$( cat /etc/issue )

  case "${distribution_name}" in
    *Ubuntu*)
      GetUbuntuOSVersion
      return 0
    ;;

    *openSUSE*)
      OS_VERSION=opensuse
      return 0
    ;;

    *Arch\ Linux*)
      printf "[x] Arch Linux is not yet supported.\n"
      return 1
    ;;

    *)
      printf "[x] ${distribution_name} is not yet a supported distribution.\n"
      return 1
    ;;
  esac
}

# Download pre-compiled version of cxx-common for this OS. This has things like
# google protobuf, gflags, glog, gtest, capstone, and llvm in it.
function DownloadLibraries
{
  # macOS packages
  if [[ "$OSTYPE" == "darwin"* ]]; then
    OS_VERSION=osx

  # Linux packages
  elif [[ "$OSTYPE" == "linux-gnu" ]]; then
    if ! GetOSVersion; then
      return 1
    fi
  else
    printf "[x] OS ${OSTYPE} is not supported.\n"
    return 1
  fi

  if ! GetArchVersion; then
    return 1
  fi

  LIBRARY_VERSION=libraries-${LLVM_VERSION}-${OS_VERSION}-${ARCH_VERSION}

  printf "[-] Library version is ${LIBRARY_VERSION}\n"

  if [[ ! -d "${BUILD_DIR}/libraries" ]]; then
    if ! DownloadCxxCommon; then
      printf "[x] Unable to download cxx-common build ${LIBRARY_VERSION}.\n"
      return 1
    fi
  fi

  return 0
}

# Configure the build.
function Configure
{
  # Tell the remill CMakeLists.txt where the extracted libraries are. 
  export TRAILOFBITS_LIBRARIES="${BUILD_DIR}/libraries"
  export PATH=“${TRAILOFBITS_LIBRARIES}/cmake/bin:${TRAILOFBITS_LIBRARIES}/llvm/bin:${PATH}”
  export CC="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang"
  export CXX="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang++"

  # Configure the remill build, specifying that it should use the pre-built
  # Clang compiler binaries.
  ${TRAILOFBITS_LIBRARIES}/cmake/bin/cmake \
      -DCMAKE_INSTALL_PREFIX=${INSTALL_DIR} \
      -DCMAKE_C_COMPILER=${CC} \
      -DCMAKE_CXX_COMPILER=${CXX} \
      -DCMAKE_VERBOSE_MAKEFILE=True \
      ${SRC_DIR}

  return $?
}

# Compile the code.
function Build
{
  if [[ "$OSTYPE" == "darwin"* ]]; then
    NPROC=$( sysctl -n hw.ncpu )
  else
    NPROC=$( nproc )
  fi
  make -j${NPROC}
  return $?
}

# Get a LLVM version name for the build. This is used to find the version of
# cxx-common to download.
function GetLLVMVersion
{
  case ${1} in
    3.5)
      LLVM_VERSION=llvm35
      return 0
    ;;
    3.6)
      LLVM_VERSION=llvm36
      return 0
    ;;
    3.7)
      LLVM_VERSION=llvm37
      return 0
    ;;
    3.8)
      LLVM_VERSION=llvm38
      return 0
    ;;
    3.9)
      LLVM_VERSION=llvm39
      return 0
    ;;
    4.0)
      LLVM_VERSION=llvm40
    ;;
    5.0)
      LLVM_VERSION=llvm50
    ;;
    *)
      # unknown option
      printf "[x] Unknown LLVM version ${1}.\n"
      exit 1
    ;;
  esac
}

function main
{
  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in

      # Change the default installation prefix.
      --prefix)
        INSTALL_DIR=$(python -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        printf "[+] New install directory is ${INSTALL_DIR}\n"
        shift # past argument
      ;;

      # Change the default LLVM version.
      --llvm-version)
        GetLLVMVersion ${2}
        if [[ $? -ne 0 ]] ; then
          return 1
        fi
        printf "[+] New LLVM version is ${LLVM_VERSION}\n"
        shift
      ;;

      # Change the default build directory.
      --build-dir)
        BUILD_DIR=$(python -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        printf "[+] New build directory is ${BUILD_DIR}\n"
        shift # past argument
      ;;

      *)
        # unknown option
        printf "[x] Unknown option: ${key}\n"
        return 1
      ;;
    esac

    shift # past argument or value
  done

  mkdir -p ${BUILD_DIR}
  cd ${BUILD_DIR}

  if ! (DownloadLibraries && Configure && Build); then
  printf "[x] Build aborted.\n"
  fi

  return $?
}

main $@
exit $?
