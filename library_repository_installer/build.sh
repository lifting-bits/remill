#!/usr/bin/env bash

function main
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tinstall_libraries.sh /path/to/destination"

        return 1
    fi

    local root_install_directory="$1"
    printf "Root install directory: ${root_install_directory}\n"

    local install_folder_name=`basename "$root_install_directory"`
    if [[ "$install_folder_name" != "libraries" ]] ; then
        printf "Please enter the full path of a folder named 'libraries'\n"
        return 1
    fi

    if [ -d "$root_install_directory" ] ; then
        rm -rf "$root_install_directory" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to erase the following folder: ${root_install_directory}\n"
            return 1
        fi
    fi

    mkdir -p "$root_install_directory" 2> /dev/null
    if [ $? -ne 0 ] ; then
        printf "Failed to create the install directory\n"
        return 1
    fi

    printf "Checking dependencies...\n"
    CheckDependencies || return 1

    InstallXED "${root_install_directory}/xed" || return 1
    InstallLLVM "${root_install_directory}/llvm" || return 1
    InstallGoogleGflags "${root_install_directory}/gflags" || return 1
    InstallGoogleTest "${root_install_directory}/googletest" || return 1
    InstallGoogleProtocolBuffers "${root_install_directory}/protobuf" || return 1
    InstallGoogleGlog "${root_install_directory}/glog" || return 1
    InstallCMakeModules "${root_install_directory}/cmake" || return 1

    rm "$LOG_FILE" 2> /dev/null

    printf "\nAdd the following line to your .bashrc/.zshenv file:\n"
    printf "  export TRAILOFBITS_LIBRARIES=${root_install_directory}\n"

    printf "\nAdd the following to your CMakeLists.txt file:\n"
    printf "  set(LIBRARY_REPOSITORY_ROOT \$ENV{TRAILOFBITS_LIBRARIES})\n"
    printf "  include(\"\${LIBRARY_REPOSITORY_ROOT}/cmake/repository.cmake\")\n"

    printf "\nYou can clean up this folder using git clean -ffdx!\n"
    return 0
}

function CheckDependencies()
{
    return 0
}

function ShowLog
{
    printf "An error as occurred and the script has terminated.\n"

    if [ ! -f "$LOG_FILE" ] ; then
        printf "No output log found\n"
        return 1
    fi

    printf "Output log follow\n================\n"
    cat "$LOG_FILE"
    printf "\n================\n"

    return 0
}

function InstallXED
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallXED /path/to/libraries"

        return 1
    fi

    printf "\nXED\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "xed" ] ; then
        printf " > Acquiring the source code...\n"
        git clone "https://github.com/intelxed/xed.git" xed >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "xed" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # acquire or update the build system for xed
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "mbuild" ] ; then
        printf " > Acquiring the build system...\n"
        git clone "https://github.com/intelxed/mbuild.git" mbuild >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the mbuild source code...\n"
        ( cd "mbuild" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install the library
    printf " > Installing...\n"
    rm "$LOG_FILE" 2> /dev/null
    ( cd xed && python2 mfile.py "--prefix=${install_directory}" install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallLLVM
{
    local llvm_branch="release_39"

    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallLLVM /path/to/libraries"

        return 1
    fi

    printf "\nLLVM\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "llvm" ] ; then
        printf " > Acquiring the source code...\n"
        git clone --depth 1 -b "$llvm_branch" "https://github.com/llvm-mirror/llvm.git" llvm >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "llvm" && git pull origin "$llvm_branch" ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # run cmake
    printf " > Configuring...\n"

    if [ ! -d "llvm-build" ] ; then
        mkdir "llvm-build" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to create the build directory for LLVM: llvm-build\n"
            return 1
        fi
    fi

    rm "$LOG_FILE" 2> /dev/null
    ( cd "llvm-build" && cmake "-DCMAKE_INSTALL_PREFIX=${install_directory}" -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DLLVM_TARGETS_TO_BUILD="X86" -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_INCLUDE_TESTS=OFF "../llvm" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install
    printf " > Building...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "llvm-build" && make -j "$PROCESSOR_COUNT" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    printf " > Installing...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "llvm-build" && make install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallGoogleGflags
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallGoogleGflags /path/to/libraries"

        return 1
    fi

    printf "\nGoogle gflags\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "gflags" ] ; then
        printf " > Acquiring the source code...\n"
        git clone "https://github.com/gflags/gflags.git" gflags >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "gflags" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # run cmake
    printf " > Configuring...\n"

    if [ ! -d "gflags-build" ] ; then
        mkdir "gflags-build" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to create the build directory for Google gflags: gflags-build\n"
            return 1
        fi
    fi

    rm "$LOG_FILE" 2> /dev/null
    ( cd "gflags-build" && cmake "-DCMAKE_INSTALL_PREFIX=${install_directory}" -DCMAKE_BUILD_TYPE="RelWithDebInfo" "../gflags" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install
    printf " > Building...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "gflags-build" && make -j "$PROCESSOR_COUNT" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    printf " > Installing...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "gflags-build" && make install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallGoogleTest
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallGoogleTest /path/to/libraries"

        return 1
    fi

    printf "\nGoogle Test\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "googletest" ] ; then
        printf " > Acquiring the source code...\n"
        git clone "https://github.com/google/googletest.git" googletest >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "googletest" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # run cmake
    printf " > Configuring...\n"

    if [ ! -d "googletest-build" ] ; then
        mkdir "googletest-build" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to create the build directory for Google googletest: googletest-build\n"
            return 1
        fi
    fi

    rm "$LOG_FILE" 2> /dev/null
    ( cd "googletest-build" && cmake "-DCMAKE_INSTALL_PREFIX=${install_directory}" -DCMAKE_BUILD_TYPE="RelWithDebInfo" "../googletest" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install
    printf " > Building...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "googletest-build" && make -j "$PROCESSOR_COUNT" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    printf " > Installing...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "googletest-build" && make install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallGoogleProtocolBuffers
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallGoogleProtocolBuffers /path/to/libraries"

        return 1
    fi

    printf "\nGoogle Protocol Buffers\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "protobuf" ] ; then
        printf " > Acquiring the source code...\n"
        git clone "https://github.com/google/protobuf.git" protobuf >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "protobuf" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # configure
    printf " > Configuring...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "protobuf" && ./autogen.sh ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    rm "$LOG_FILE" 2> /dev/null
    ( cd "protobuf" && ./configure "--prefix=${install_directory}" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install
    printf " > Building...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "protobuf" && make -j "$PROCESSOR_COUNT" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    printf " > Installing...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "protobuf" && make install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallGoogleGlog
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallGoogleGlog /path/to/libraries"

        return 1
    fi

    printf "\nGoogle Logging module\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    # acquire or update the source code
    rm "$LOG_FILE" 2> /dev/null
    if [ ! -d "glog" ] ; then
        printf " > Acquiring the source code...\n"
        git clone "https://github.com/google/glog.git" glog >> "$LOG_FILE" 2>&1
    else
        printf " > Updating the source code...\n"
        ( cd "glog" && git pull origin master ) >> "$LOG_FILE" 2>&1
    fi

    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # run cmake
    printf " > Configuring...\n"

    if [ ! -d "glog-build" ] ; then
        mkdir "glog-build" 2> /dev/null
        if [ $? -ne 0 ] ; then
            printf "Failed to create the build directory for Google glog: glog-build\n"
            return 1
        fi
    fi

    rm "$LOG_FILE" 2> /dev/null
    ( cd "glog-build" && cmake "-DCMAKE_INSTALL_PREFIX=${install_directory}" -DCMAKE_BUILD_TYPE="RelWithDebInfo" "../glog" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    # build and install
    printf " > Building...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "glog-build" && make -j "$PROCESSOR_COUNT" ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    printf " > Installing...\n"

    rm "$LOG_FILE" 2> /dev/null
    ( cd "glog-build" && make install ) >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

function InstallCMakeModules
{
    if [ $# -ne 1 ] ; then
        printf "Usage:\n"
        printf "\tInstallCMakeModules /path/to/libraries"

        return 1
    fi

    printf "\nCMake modules...\n"

    local install_directory="$1"
    printf " > Install directory: ${install_directory}\n"

    printf " > Copying...\n"
    rm "$LOG_FILE" 2> /dev/null
    cp -rp cmake "$install_directory" >> "$LOG_FILE" 2>&1
    if [ $? -ne 0 ] ; then
        ShowLog
        return 1
    fi

    return 0
}

LOG_FILE="installer.log"

if [[ "$OSTYPE" == "darwin"* ]]; then
    PROCESSOR_COUNT=`sysctl -n hw.ncpu`
else
    PROCESSOR_COUNT=`nproc`
fi

main $@
exit $?
