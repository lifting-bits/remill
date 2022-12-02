#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
PROJECT=remill

BUILDLOG=${PROJECT}-build.log
CONFIGLOG=${PROJECT}-configure.log
rm -f ${BUILDLOG} ${CONFIGLOG}
BUILD_TYPE=dbg
VCPKG_SUFFIX="-rel"

set -o pipefail

function sanity_check {
	if [ -z "${CMAKE_TOOLCHAIN_FILE}" ]; then
		echo "Please set the CMAKE_TOOLCHAIN_FILE environment variable to the CMake toolchain file to build against"
		exit 1
	else
		echo "Building against CMake toolchain file: [${CMAKE_TOOLCHAIN_FILE}]"
	fi

	if [ -z "${INSTALL_DIR}" ]; then
		echo "Please set the INSTALL_DIR environment variable to the desired installation directory"
		exit 1
	else
		echo "Installing to: [${INSTALL_DIR}]"
	fi
}

function show_usage {

  printf "${0}: Build ${PROJECT} <debug|release> [-- extra arguments to CMake]"
  printf "\n"
  printf "\t--help: this screen\n"
  printf "\t--debug-vcpkg: build against a debug vcpkg (default OFF)\n"
  printf "\t<debug|release>: the type of build to do (debug or release)\n"
  printf "\tArguments after '--' are passed to CMake during configuration (e.g. -DCMAKE_C_COMPILER=foo)\n"
  printf "\n"
  printf "INSTALL_DIR set to [${INSTALL_DIR}]\n"
  printf "CMAKE_TOOLCHAIN_FILE set to [${CMAKE_TOOLCHAIN_FILE}]\n"

  return 0
}

function set_arch {
  local arch=$(uname -m)
  case ${arch} in
    aarch64 | arm64)
      echo "arm64"
      ;;
    x86_64)
      echo "x64"
      ;;
    *)
      echo "Unknown architecture: ${arch}"
      exit 1
  esac
}

function set_os {
  local os=$(uname -s)
  case ${os} in
    Darwin)
      echo "osx"
      ;;
    Linux)
      echo "linux"
      ;;
    *)
      echo "Unknown OS: ${os}"
      exit 1
  esac
}


# Make the user specify which build type
if [[ $# -eq 0 ]]; then
    show_usage ${0}
    exit 0
fi

# check if proper env vars are set
sanity_check

# Look for help or set the build type
while [[ $# -gt 0 ]]
do
    key="$1"
    case $key in
        --help | -h | "-?")
        show_usage ${0}
        exit 0
        ;;
        --debug-vcpkg)
        VCPKG_SUFFIX=""
        shift
        ;;
        debug)
        BUILD_TYPE="dbg"
        shift
        ;;
        release)
        BUILD_TYPE="rel"
        shift
        ;;
        "--")
        shift
        break
        ;;
        *)    # unknown option
        echo "UNKNOWN OPTION: ${1}"
        echo "Usage:"
				show_usage ${0}
        exit 1
        ;;
    esac
done

ARCH=$(set_arch)
OS=$(set_os)
export VCPKG_TARGET_TRIPLET=${ARCH}-${OS}${VCPKG_SUFFIX}

echo "Configuring [${BUILD_TYPE}] [${ARCH}] against vcpkg [${VCPKG_TARGET_TRIPLET}]..."
if [[ "${@}" != "" ]]
then
  echo "Passing extra arguments to CMake: ${@}"
fi

cmake --preset vcpkg-${ARCH}-${BUILD_TYPE} ${@} &>${CONFIGLOG}
if [ "$?" != "0" ]; then
  echo "Configuration failed. See ${CONFIGLOG}"
  echo "Last 10 lines are:"
  tail -n 10 "${CONFIGLOG}"
  exit 1
else
  echo "Configure success!"
fi

echo "Building [${BUILD_TYPE}] [${ARCH}]..."
cmake --build --preset ${ARCH}-${BUILD_TYPE} --parallel &>${BUILDLOG}
if [ "$?" != "0" ]; then
  echo "Build failed. See ${BUILDLOG}"
  echo "Last 10 lines are:"
  tail -n 10 "${BUILDLOG}"
  exit 1
else
  echo "Build success!"
fi

echo "Installing [${BUILD_TYPE}] [${ARCH}]..."
# re-use build log since its mostly a part of build process
cmake --build --preset ${ARCH}-${BUILD_TYPE} --target install --parallel >>${BUILDLOG} 2>&1
if [ "$?" != "0" ]; then
  echo "Install failed. See ${BUILDLOG}"
  echo "Last 10 lines are:"
  tail -n 10 "${BUILDLOG}"
  exit 1
else
  echo "Install success!"
fi
