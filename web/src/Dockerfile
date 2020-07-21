FROM ubuntu:19.10@sha256:bd5f4f235eb31768b2c5caf1988bbdc182d4fc3cb6ee4aca6c6d74613f256140

RUN apt-get update
RUN apt-get install -y \
      git

RUN git config --global advice.detachedHead false

# Checkout all the releases at specific tags to ensure updates don't break the build.
ENV REPOS="/repos"
WORKDIR "$REPOS"
RUN git clone https://github.com/llvm/llvm-project.git
RUN cd llvm-project && git checkout llvmorg-10.0.0-rc2
RUN git clone https://github.com/juj/emsdk.git
RUN cd emsdk && git checkout 1458145cf4f3db0fb548343e6acab267eef8e4ef
RUN git clone https://github.com/intelxed/xed.git
RUN cd xed && git checkout 11.0.1
RUN git clone https://github.com/intelxed/mbuild.git
RUN cd mbuild && git checkout 1e57534e2122a39382c68e134026b15a3370e5b1
RUN git clone https://github.com/gflags/gflags.git
RUN cd gflags && git checkout v2.2.2
RUN git clone https://github.com/google/glog.git
RUN cd glog && git checkout v0.4.0

RUN apt-get install -y \
      build-essential \
      ccache \
      clang \
      cmake \
      curl \
      default-jre \
      emscripten \
      libtinfo-dev \
      llvm \
      lsb-release \
      ninja-build \
      patchelf \
      python2.7 \
      wget \
      zlib1g-dev

# Download a specific version of Emscripten (fastcomp fails with linker errors, upstream is required).
ENV EMSCRIPTEN_VERSION sdk-tag-1.39.7-64bit-upstream
RUN cd emsdk && \
    ./emsdk update-tags && \
    ./emsdk install $EMSCRIPTEN_VERSION && \
    ./emsdk activate --embedded $EMSCRIPTEN_VERSION

ENV EMSDK="$REPOS/emsdk"
ENV EMSDK_NODE_BIN="$EMSDK/node/12.9.1_64bit/bin"
ENV EMSCRIPTEN="$EMSDK/upstream/emscripten"
ENV PATH="$EMSDK:$EMSCRIPTEN:$EMSDK_NODE_BIN:${PATH}"
ENV EM_CONFIG="$EMSDK/.emscripten"
ENV EM_PORTS="$EMSDK/.emscripten_ports"
ENV EM_CACHE="$EMSDK/.emscripten_cache"
ENV EMSDK_NODE="$EMSDK_NODE_BIN/node"
ENV EM_TOOLCHAIN="$EMSCRIPTEN/cmake/Modules/Platform/Emscripten.cmake"
ENV EMCC_WASM_BACKEND=1
ENV EMCC_SKIP_SANITY_CHECK=1

ENV EM_CXX_FLAGS="-s ERROR_ON_UNDEFINED_SYMBOLS=0 -s USE_PTHREADS=0 -s WASM=1 -Wno-everything -O2 --closure 1 --llvm-lto 3"

# ===== Build llvm-tblgen on Host =====
# Building all of LLVM requires its own tool 'llvm-tblgen', however we can't use the Ubuntu package "llvm"
# because it is too old and doesn't have the latest wasm changes, so build a host version ourselves.
# Moreover, when building LLVM under Emscripten it will try and build tblgen but won't be able to run it 
# since it's a .js file, not an exectuable. Therefore below we manually specify -DLLVM_TABLEGEN=...
RUN mkdir -p "$REPOS/llvm-project/build"
WORKDIR "$REPOS/llvm-project/build"
RUN cmake \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      ../llvm
RUN cmake --build . --target llvm-tblgen

# ===== Build LLVM on Emscripten =====
WORKDIR "$REPOS"
# LLVM attempts to check the compiler version but Emscripten's emcc outputs its version
# in a different format that can't be parsed by LLVM (a PR could be submitted upstream).
RUN echo "" > llvm-project/llvm/cmake/modules/CheckCompilerVersion.cmake

RUN mkdir -p "$REPOS/llvm-project/llvm/build"
WORKDIR "$REPOS/llvm-project/llvm/build"

RUN cmake \
      -Wno-deprecated \
      -Wno-dev \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DLLVM_DEFAULT_TARGET_TRIPLE=wasm32-unknown-unknown-wasm \
      -DLLVM_ENABLE_THREADS=OFF \
      -DLLVM_USE_SANITIZER=OFF \
      -DLLVM_ENABLE_EXPENSIVE_CHECKS=OFF \
      -DLLVM_ENABLE_BACKTRACES=OFF \
      -DLLVM_ENABLE_DUMP=OFF \
      -DLLVM_INCLUDE_TESTS=OFF \
      -DLLVM_INCLUDE_TOOLS=ON \
      -DLLVM_BUILD_TOOLS=ON \
      -DLLVM_BUILD_LLVM_DYLIB=ON \
      -DLLVM_LINK_LLVM_DYLIB=ON \
      -DLLVM_ENABLE_TERMINFO=OFF \
      -DLLVM_TARGETS_TO_BUILD= \
      -DLLVM_EXPERIMENTAL_TARGETS_TO_BUILD=WebAssembly \
      -DLLVM_TABLEGEN=$REPOS/llvm-project/build/bin/llvm-tblgen \
      -DCMAKE_TOOLCHAIN_FILE="$EM_TOOLCHAIN" \
      -DCMAKE_CXX_FLAGS="$EM_CXX_FLAGS" \
      -DCMAKE_STRIP=llvm-strip \
      -DCMAKE_AR="$EMSCRIPTEN/emar" \
      ..

RUN cmake --build . --target LLVM

# ===== Build XED on Emscripten =====
WORKDIR "$REPOS/xed"
RUN ./mfile.py \
      --cc=emcc \
      --cxx=em++ \
      --linker=wasm-ld \
      --ar=emar \
      --host-cpu=x86 \
      --extra-cxxflags="$EM_CXX_FLAGS" \
      --extra-ccflags="$EM_CXX_FLAGS"

# ===== Build gflags on Emscripten =====
WORKDIR "$REPOS"
RUN mkdir -p "$REPOS/gflags/build"
WORKDIR "$REPOS/gflags/build"
RUN cmake \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE="$EM_TOOLCHAIN" \
      -DCMAKE_CXX_FLAGS="$EM_CXX_FLAGS" \
      ..
RUN cmake --build .

# ===== Build glog on Emscripten =====
WORKDIR "$REPOS"
RUN sed -i 's/\bHAVE_SYMBOLIZE 1\b/HAVE_SYMBOLIZE 0/g' glog/CMakeLists.txt
RUN mkdir -p "$REPOS/glog/build"
WORKDIR "$REPOS/glog/build"
RUN cmake \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_TOOLCHAIN_FILE="$EM_TOOLCHAIN" \
      -DCMAKE_CXX_FLAGS="$EM_CXX_FLAGS" \
      -DBUILD_TESTING=OFF \
      -Dgflags_DIR="$REPOS/gflags/build" \
      ..

# Emscripten has a syscall.h, however it does not implement the exact signature for syscall
# and glog attempts to call it if the header exists, so just pretend it doesn't exist.
RUN sed -i 's/\bHAVE_SYSCALL_H\b/HAVE_SYSCALL_H_INVALID/g' config.h
RUN sed -i 's/\bHAVE_SYS_SYSCALL_H\b/HAVE_SYS_SYSCALL_H_INVALID/g' config.h

RUN cmake --build .

# ===== Build remill on Emscripten =====
WORKDIR "$REPOS"

# Bypass a remill CMake error about finding clang.
# This compiler is not used under Emscripten since it has it's own installed version of clang.
# The version must match the checked out version of llvm-project.
RUN cp /usr/bin/clang /usr/bin/clang-10.0

# The emscripten cache needs to be usable by the outside user (currently owned by root).
RUN chmod -R 666 "$EMSDK/.emscripten_cache.lock"