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

#set -e

# build and output directories (by default, install in the same folder as the git repository)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=$(readlink -f ${DIR})/build
THIRD_PARTY_DIR=$(readlink -f ${DIR})/third_party
PREFIX=${BUILD_DIR}

# locate the osx sdk
OSX_SDK=

which xcrun > /dev/null 2>&1
if [ $? -eq 0 ] ; then
  OSX_SDK=$(xcrun -sdk macosx --show-sdk-path)
fi

# set the default compiler if no one is currently selected
CC=${CC:-clang}
CXX=${CXX:-clang++}

# default argument values
BUILD_TYPE=Debug

function main
{
  #
  # parse the arguments
  #

  # taken from: http://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in
      -p|--prefix)
      PREFIX=$(readlink -f $2)
      shift # past argument
    ;;

    -b|--build)
      BUILD_TYPE="$2"
      shift # past argument
    ;;

    *)
      # unknown option
      echo "Unknown option: $key"
      ShowUsage

      return 1
    ;;
    esac

    shift # past argument or value
  done

  if [ ! -d "${PREFIX}" ]; then
    echo "Cannot find installation prefix directory: ${PREFIX}"
    exit 1
  else
      echo "Installation directory prefix: ${PREFIX}"
  fi

  DEBUG_BUILD_ARGS=

  local job_count="$NPROC"
  if [ -z "$job_count" ] ; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      job_count=$(sysctl -n hw.ncpu)
    else
      job_count=`nproc`
    fi
  fi

  echo "Make job count: $job_count"

  echo "Build type set to: ${BUILD_TYPE}"
  if [[ "${BUILD_TYPE}" == "Debug" ]]; then
    echo "  Setting build arguments for DCMAKE_BUILD_TYPE=Debug"

    BUILD_TYPE=Debug
    DEBUG_BUILD_ARGS="-g3 -O0"
  fi

  #
  # install the required dependencies
  #

  echo "[+] Creating '${BUILD_DIR}'"
  mkdir -p ${BUILD_DIR}

  REMILL_DIR=$(realpath ${DIR})
  BUILD_DIR=$(realpath ${BUILD_DIR})

  InstallPackages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  InstallPythonPackages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  InstallDependencies
  if [ $? -ne 0 ] ; then
    return 1
  fi

  BuildRemill
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# installs the required packages for the system in use
# returns 0 in case of success or 1 otherwise
function InstallPackages
{
  # mac os x packages
  if [[ "$OSTYPE" == "darwin"* ]]; then
    local osx_dependencies="wget git cmake coreutils"

    brew install $osx_dependencies
    if [ $? -ne 0 ] ; then
      echo "Brew has failed to install the following packages: ${osx_dependencies}. Continuing anyway..."
      return 1
    fi

    return 0

  # unsupported systems
  elif [[ "$OSTYPE" != "linux-gnu" ]]; then
    return 1
  fi

  # attempt to detect the distribution
  local distribution_name=`cat /etc/issue`

  case "$distribution_name" in
    *Ubuntu*)
      InstallUbuntuPackages
      return $?
    ;;

    *Arch\ Linux*)
      InstallArchLinuxPackages
      return $?
    ;;

    *)
      printf '[x] Failed to install the required dependencies; please make sure the following packages are installed: git, cmake, protobuf, python 2, pip 2, llvm, clang\n'
      return 0
  esac
}

# installs the required packages for ubuntu
# returns 0 in case of success or 1 otherwise
function InstallUbuntuPackages
{
  local required_package_list=(
    'git'
    'cmake'
    'libprotoc-dev'
    'libprotobuf-dev'
    'protobuf-compiler'
    'python2.7'
    'python-pip'
    'realpath'

    # gcc-multilib required only for 32-bit integration tests
    # g++-multilib required to build 32-bit generated code

    'gcc-multilib'
    'g++-multilib'

    # liblzma-dev needed for the xz integration test
    # libpcre3-dev needed for some integration tests
    # libbsd-dev needed for netcat test

    'liblzma-dev'
    'libpcre3-dev'
    'libbsd-dev'
  )

  local installed_package_list=`dpkg -l | tail -n+6 | awk '{ print $2 }'`
  local missing_packages=""

  for required_package in ${required_package_list[@]} ; do
    if [[ ${installed_package_list} == *"$required_package"* ]] ; then
      continue
    fi

    missing_packages="$missing_packages $required_package"
  done

  if [ -z "$missing_packages" ] ; then
    echo "[+] All the required dependencies are installed. Continuing..."
    return 0
  fi

  echo "[+] Installing dependencies..."

  sudo apt-get update -qq
  if [ $? -ne 0 ] ; then
    return 1
  fi

  sudo apt-get install -yqq $missing_packages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# installs the required packages for arch linux
# returns 0 in case of success or 1 otherwise
function InstallArchLinuxPackages
{
  local required_package_list=(
    'git'
    'cmake'
    'protobuf'
    'protobuf-c'
    'python2'
    'python2-pip'
    'clang'
    'llvm'

    # liblzma-dev needed for the xz integration test
    # libpcre3-dev needed for some integration tests
    # libbsd-dev needed for netcat test

    'pcre'
    'libbsd'
    'xz'
  )

  local installed_package_list=`pacman -Q | awk '{ print $1 }'`
  local missing_packages=""

  for required_package in ${required_package_list[@]} ; do
    if [[ ${installed_package_list} == *"$required_package"* ]] ; then
      continue
    fi

    missing_packages="$missing_packages $required_package"
  done

  if [ -z "$missing_packages" ] ; then
    echo "[+] All the required dependencies are installed. Continuing..."
    return 0
  fi

  echo "[+] Installing dependencies..."
  sudo pacman -S $missing_packages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# Installs dependencies (XED, GTest)
function InstallDependencies
{
  pushd ${BUILD_DIR}
  echo "[+] Installing XED"
  PREFIX="${PREFIX}" ${REMILL_DIR}/scripts/unix/install_xed.sh
  if [ $? -ne 0 ] ; then
    echo "Failed to install XED"
    return 1
  fi

  popd
  return 0
}

# locates the correct python version
# returns the executable path in case of success, or an empty string otherwise
function GetPythonLocation
{
  which python2 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local python_path=`which python2`
  fi

  if [ -z "$python_path" ] ; then
    which python > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      local python_path=`which python`
    fi
  fi

  "$python_path" --version 2>&1 | grep 2.7 > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    echo ""
    return
  fi

  printf "$python_path"
}

# locates the correct pip path (some distributions use Python 3 as default interpreter)
# returns the pip path in case of success, or an empty string otherwise
function GetPythonPIPLocation
{
  which pip2 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local pip_path=`which pip2`
  fi

  if [ -z "$pip_path" ] ; then
    which pip > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      local pip_path=`which pip`
    fi
  fi

  "$pip_path" --version 2>&1 | grep 2.7 > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    echo ""
    return
  fi

  printf "$pip_path"
}

# updates pip and installs the protobuf dependency
# returns 0 in case of success, or 1 otherwise
function InstallPythonPackages
{
  local pip_path=`GetPythonPIPLocation`
  if [ -z "$pip_path" ] ; then
    echo "Failed to locate the PIP executable"
    return 1
  fi

  echo "[+] Upgrading PIP"
  sudo -H "$pip_path" install --upgrade pip
  if [ $? -ne 0 ] ; then
    echo "Failed to upgrade PIP"
    return 1
  fi

  echo "[+] Installing python-protobuf"
  sudo -H "$pip_path" install 'protobuf==2.6.1'
  if [ $? -ne 0 ] ; then
    echo "Failed to install protobuf with PIP"
    return 1
  fi

  if [ -d /usr/local/lib/python2.7/dist-packages/google ] ; then
    sudo touch /usr/local/lib/python2.7/dist-packages/google/__init__.py
    if [ $? -ne 0 ] ; then
      echo "Failed to create the following file: /usr/local/lib/python2.7/dist-packages/google/__init__.py"
      return 1
    fi
  fi

  return 0
}

# builds mcsema, installing it inside the prefix directory
# returns 0 in case of success, or 1 otherwise
function BuildRemill
{
  pushd ${BUILD_DIR}

  local python_path=`GetPythonLocation`
  if [ -z "$python_path" ] ; then
    echo "Failed to locate a suitable python interpreter"
    return 1
  fi

  echo "[+] Configuring: Remill"

  CC=/data/llvm-3.9/install/bin/clang
  CXX=/data/llvm-3.9/install/bin/clang++

  CC=${CC} \
  CXX=${CXX} \
  cmake \
    -G "Unix Makefiles" \
    -DCMAKE_INSTALL_PREFIX="${PREFIX}" \
    -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
    -DPYTHON_PATH="${python_path}" \
    ${REMILL_DIR}

  if [ $? -ne 0 ] ; then
    echo "CMake could not generate the makefiles for Remill"
    return 1
  fi

  echo "[+] Building: Remill"

  make -j${job_count}
  if [ $? -ne 0 ] ; then
    echo "Failed to build Remill"
    return 1
  fi

  echo "[+] Installing: Remill"

  make install
  if [ $? -ne 0 ] ; then
    echo "Failed to install Remill to the prefix directory"
    return 1
  fi

  popd

  return 0
}

function ShowUsage() {
  echo "Usage:"
  echo "$0 [--prefix <PREFIX>] [--build <BUILD TYPE>] [--enable-rtti]"
  echo "PREFIX: Installation directory prefix"
  echo "BUILDTYPE: Built type (e.g. Debug, Release, etc.)"
}

main $@
exit $?
