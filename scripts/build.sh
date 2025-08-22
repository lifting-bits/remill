#!/usr/bin/env bash
# Copyright (c) 2019 Trail of Bits, Inc.
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
DOWNLOAD_DIR="$( cd "$( dirname "${SRC_DIR}" )" && pwd )/lifting-bits-downloads"
CURR_DIR=$( pwd )
BUILD_DIR="${CURR_DIR}/remill-build"
INSTALL_DIR=/usr/local
LLVM_VERSION=llvm-17
OS_VERSION=
ARCH_VERSION=
BUILD_FLAGS=
CXX_COMMON_VERSION="0.6.0"
CREATE_PACKAGES=true

# There are pre-build versions of various libraries for specific
# Ubuntu releases.
function GetUbuntuOSVersion
{
  # Version name of OS (e.g. xenial, trusty).
  source /etc/lsb-release

  case "${DISTRIB_CODENAME}" in
    lunar)
      echo "[!] Ubuntu 23.04 is not supported; using libraries for Ubuntu 22.04 instead"
      OS_VERSION=ubuntu-22.04
      return 0
    ;;
    kinetic)
      echo "[!] Ubuntu 22.10 is not supported; using libraries for Ubuntu 22.04 instead"
      OS_VERSION=ubuntu-22.04
      return 0
    ;;
    jammy)
      OS_VERSION=ubuntu-22.04
      return 0
    ;;
    *)
      echo "[x] Ubuntu ${DISTRIB_CODENAME} is not supported. Only jammy (22.04) is supported."
      return 1
    ;;
  esac
}

# Figure out the architecture of the current machine.
function GetArchVersion
{
  local version
  version="$( uname -m )"

  case "${version}" in
    x86_64)
      ARCH_VERSION=amd64
      return 0
    ;;
    x86-64)
      ARCH_VERSION=amd64
      return 0
    ;;
    arm64 | aarch64)
      ARCH_VERSION=arm64
      return 0
    ;;
    *)
      echo "[x] ${version} architecture is not supported. Only aarch64 and x86_64 (i.e. amd64) are supported."
      return 1
    ;;
  esac
}

function DownloadVcpkgLibraries
{
  local GITHUB_LIBS="${LIBRARY_VERSION}.tar.xz"
  local URL="https://github.com/lifting-bits/cxx-common/releases/download/v${CXX_COMMON_VERSION}/${GITHUB_LIBS}"

  mkdir -p "${DOWNLOAD_DIR}"
  pushd "${DOWNLOAD_DIR}" || return 1

  echo "Fetching: ${URL} and placing in ${DOWNLOAD_DIR}"
  if ! curl -LO "${URL}"; then
    return 1
  fi

  local TAR_OPTIONS="--warning=no-timestamp"
  if [[ "$OSTYPE" == "darwin"* ]]; then
    TAR_OPTIONS=""
  fi

  (
    set -x
    tar -xJf "${GITHUB_LIBS}" ${TAR_OPTIONS}
  ) || return $?
  rm "${GITHUB_LIBS}"
  popd || return 1

  # Make sure modification times are not in the future.
  find "${DOWNLOAD_DIR}/${LIBRARY_VERSION}" -type f -exec touch {} \;

  return 0
}

# Attempt to detect the OS distribution name.
function GetOSVersion
{
  source /etc/os-release

  case "${ID,,}" in
    *ubuntu*)
      GetUbuntuOSVersion
      return 0
    ;;

    *debian*)
      OS_VERSION=ubuntu-22.04
      return 0
    ;;

    *arch*)
      OS_VERSION=ubuntu-22.04
      return 0
    ;;

    [Kk]ali)
      OS_VERSION=ubuntu-22.04
      return 0;
    ;;

    *)
      echo "[x] ${ID} is not yet a supported distribution."
      return 1
    ;;
  esac
}

# Download pre-compiled version of cxx-common for this OS. This has things like
# google protobuf, gflags, glog, gtest, capstone, and llvm in it.
function DownloadLibraries
{
  # macOS packages
  if [[ "${OSTYPE}" = "darwin"* ]]; then

    # Compute an isysroot from the SDK root dir.
    #local sdk_root="${SDKROOT}"
    #if [[ "x${sdk_root}x" = "xx" ]]; then
    #  sdk_root=$(xcrun -sdk macosx --show-sdk-path)
    #fi

    #BUILD_FLAGS="${BUILD_FLAGS} -DCMAKE_OSX_SYSROOT=${sdk_root}"
    # Min version supported
    OS_VERSION="macos-13"
    # Hard-coded to match pre-built binaries in CI
    XCODE_VERSION="15.0"
    SYSTEM_VERSION=$(sw_vers -productVersion)
    if [[ "${SYSTEM_VERSION}" == "13.*" ]]; then
      echo "Found MacOS Ventura"
      OS_VERSION="macos-12"
    elif [[ "${SYSTEM_VERSION}" == "12.*" ]]; then
      echo "Found MacOS Monterey"
      OS_VERSION="macos-12"
    else
      echo "WARNING: ****Likely unsupported MacOS Version****"
      echo "WARNING: ****Using ${OS_VERSION}****"
    fi

  # Linux packages
  elif [[ "${OSTYPE}" = "linux-gnu" ]]; then
    if ! GetOSVersion; then
      return 1
    fi
  else
    echo "[x] OS ${OSTYPE} is not supported."
    return 1
  fi

  if ! GetArchVersion; then
    return 1
  fi

  VCPKG_TARGET_ARCH="${ARCH_VERSION}"
  if [[ "${VCPKG_TARGET_ARCH}" == "amd64" ]]; then
    VCPKG_TARGET_ARCH="x64"
  fi

  if [[ "${OS_VERSION}" == "macos-"* ]]; then
    # TODO Figure out Xcode compatibility
    LIBRARY_VERSION="vcpkg_${OS_VERSION}_${LLVM_VERSION}_xcode-${XCODE_VERSION}_${ARCH_VERSION}"
    VCPKG_TARGET_TRIPLET="${VCPKG_TARGET_ARCH}-osx-rel"
  else
    # TODO Arch version
    LIBRARY_VERSION="vcpkg_${OS_VERSION}_${LLVM_VERSION}_${ARCH_VERSION}"
    VCPKG_TARGET_TRIPLET="${VCPKG_TARGET_ARCH}-linux-rel"
  fi

  echo "[-] Library version is ${LIBRARY_VERSION}"

  if [[ ! -d "${DOWNLOAD_DIR}/${LIBRARY_VERSION}" ]]; then
    if ! DownloadVcpkgLibraries; then
      echo "[x] Unable to download vcpkg libraries build ${LIBRARY_VERSION}."
      return 1
    fi
  fi

  return 0
}

# Configure the build.
function Configure
{
  # Configure the remill build, specifying that it should use the pre-built
  # Clang compiler binaries.
  (
    set -x
    cmake \
        -DCMAKE_INSTALL_PREFIX="${INSTALL_DIR}" \
        -GNinja \
        -DCMAKE_TOOLCHAIN_FILE="${DOWNLOAD_DIR}/${LIBRARY_VERSION}/scripts/buildsystems/vcpkg.cmake" \
        -DVCPKG_TARGET_TRIPLET="${VCPKG_TARGET_TRIPLET}" \
        ${BUILD_FLAGS} \
        "${SRC_DIR}"
  ) || exit $?

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

  (
    set -x
    cmake --build . -- -j"${NPROC}" -v
  ) || return $?

  return $?
}

#Install only
function Install
{
  (
    set -x
    cmake --build . \
      --target install

  ) || return $?

  return $?
}

# Create the packages
function Package
{
  remill_tag=$(cd "${SRC_DIR}" && git describe --tags --always --abbrev=0)
  remill_commit=$(cd "${SRC_DIR}" && git rev-parse HEAD | cut -c1-7)
  remill_version="${remill_tag:1}.${remill_commit}"

  (
    set -x

    if [[ -d "install" ]]; then
      rm -rf "install"
    fi

    mkdir "install"
    export DESTDIR="$(pwd)/install"

    cmake --build . \
      --target install


    if [ "$CREATE_PACKAGES" = true ]; then
      cpack -D REMILL_DATA_PATH="${DESTDIR}" \
        -R ${remill_version} \
        --config "${SRC_DIR}/packaging/main.cmake"
    fi
  ) || return $?

  return $?
}

# Get a LLVM version name for the build. This is used to find the version of
# cxx-common to download.
function GetLLVMVersion
{
  case ${1} in
    15)
      LLVM_VERSION=llvm-15
      return 0
    ;;
    16)
      LLVM_VERSION=llvm-16
      return 0
    ;;
    17)
      LLVM_VERSION=llvm-17
      return 0
    ;;
    *)
      # unknown option
      echo "[x] Unknown or unsupported LLVM version ${1}. You may be able to manually build it with cxx-common."
      return 1
    ;;
  esac
  return 1
}

function Help
{
  echo "Beginner build script to get started"
  echo ""
  echo "Options:"
  echo "  --prefix           Change the default (${INSTALL_DIR}) installation prefix."
  echo "  --llvm-version     Change the default (15) LLVM version."
  echo "  --build-dir        Change the default (${BUILD_DIR}) build directory."
  echo "  --debug            Build with Debug symbols."
  echo "  --extra-cmake-args Extra CMake arguments to build with."
  echo "  --install          Just install Remill, do not package it."
  echo "  --dyinst-frontend  Build McSema with dyninst frontend as well."
  echo "  -h --help          Print help."
}

function main
{
  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in

      -h)
        Help
        exit 0
      ;;

      --help)
        Help
        exit 0
      ;;

      # Change the default installation prefix.
      --prefix)
        INSTALL_DIR=$(python3 -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        echo "[+] New install directory is ${INSTALL_DIR}"
        shift # past argument
      ;;

      # Change the default LLVM version.
      --llvm-version)
        if ! GetLLVMVersion "${2}" ; then
          return 1
        fi
        echo "[+] New LLVM version is ${LLVM_VERSION}"
        shift
      ;;

      # Change the default build directory.
      --build-dir)
        BUILD_DIR=$(python3 -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        echo "[+] New build directory is ${BUILD_DIR}"
        shift # past argument
      ;;

      # Change the default download directory.
      --download-dir)
        DOWNLOAD_DIR=$(python3 -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        echo "[+] New download directory is ${BUILD_DIR}"
        shift # past argument
      ;;

      # Disable packages
      --disable-package)
        CREATE_PACKAGES=false
        echo "[+] Disabled building packages"
        shift # past argument
      ;;


      # Make the build type to be a debug build.
      --debug)
        BUILD_FLAGS="${BUILD_FLAGS} -DCMAKE_BUILD_TYPE=Debug"
        echo "[+] Enabling a debug build of remill"
      ;;

      # Only install, do not pakage
      --install)
        INSTALL_ONLY="yes"
        echo "[+] Install only. No packaging will be done."
      ;;

      --extra-cmake-args)
        BUILD_FLAGS="${BUILD_FLAGS} ${2}"
        echo "[+] Will supply additional arguments to cmake: ${BUILD_FLAGS}"
        shift
      ;;

      # tell McSema to build dyninst frontend as well
      --dyninst-frontend)
        GetOSVersion
        if [[ $OS_VERSION != ubuntu* ]] ; then
          echo "[+] Dyninst frontend is supported only on Ubuntu, try at your own peril"
          read -p "Continue? (Y/N): " confirm
          case $confirm in
            y|Y ) echo "Confirmed";;
            n|N ) exit 1;;
            * ) echo "Unknown option" && exit 1;;
          esac
        fi
        BUILD_FLAGS="${BUILD_FLAGS} -DBUILD_MCSEMA_DYNINST_DISASS=1"
        echo "[+] Will build dyninst frontend"
      ;;

      *)
        # unknown option
        echo "[x] Unknown option: ${key}"
        return 1
      ;;
    esac

    shift # past argument or value
  done

  mkdir -p "${BUILD_DIR}"
  cd "${BUILD_DIR}" || exit 1

  if ! (DownloadLibraries && Configure && Build ); then
    echo "[x] Build aborted."
    exit 1
  fi

  if [[ "${INSTALL_ONLY}" = "yes" ]]
  then
    if ! Install; then
      echo "[x] Installation Failed"
    fi
  else
    if ! Package; then
      echo "[x] Packaging Failed"
    fi
  fi

  return $?
}

main "$@"
exit $?
