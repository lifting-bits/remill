# Choose your LLVM version (16+)
ARG LLVM_VERSION=16
ARG ARCH=aarch64
ARG UBUNTU_VERSION=22.04

# base ubuntu stage
FROM ubuntu:${UBUNTU_VERSION} as base
ARG LLVM_VERSION
ARG ARCH
ARG UBUNTU_VERSION

# Run-time dependencies go here
FROM base as deps
RUN apt-get update && apt-get install -qqy --no-install-recommends apt-transport-https software-properties-common gnupg ca-certificates wget && \
apt-add-repository ppa:git-core/ppa --yes

RUN apt-get update && \
  if [ "$( uname -m )" = "x86_64" ]; then \
    dpkg --add-architecture i386 && apt-get update && apt-get install -qqy gcc-multilib g++-multilib zlib1g-dev:i386; \
  elif [ "$( uname -m )" = "aarch64" ]; then \
    dpkg --add-architecture armhf && apt-get update && apt-get install -qqy libstdc++-*-dev-armhf-cross; \
  fi

### cmake install
RUN wget "https://github.com/Kitware/CMake/releases/download/v3.22.1/cmake-3.22.1-linux-$(uname -m).sh" && \
/bin/bash cmake-*.sh --skip-license --prefix=/usr/local && rm cmake-*.sh

### set llvm package URL to sources.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  if [ "$( lsb_release -sr )" = "22.04" ]; then \
    echo "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/jammy/ llvm-toolchain-jammy-${LLVM_VERSION} main" >> /etc/apt/sources.list; \
  elif [ "$( lsb_release -sr )" = "20.04" ]; then \
    echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-${LLVM_VERSION} main" >> /etc/apt/sources.list && \
    echo "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-${LLVM_VERSION} main" >> /etc/apt/sources.list; \
  fi

### several packages install
RUN apt-get update && apt-get install -qqy --no-install-recommends libtinfo-dev libzstd-dev python3-pip python3-setuptools python-setuptools python3 build-essential \
    clang-${LLVM_VERSION} lld-${LLVM_VERSION} libstdc++-*-dev-armhf-cross ninja-build pixz xz-utils make rpm curl unzip tar git zip pkg-config vim \
    libc6-dev liblzma-dev zlib1g-dev libselinux1-dev libbsd-dev ccache binutils-dev libelf-dev && \   
    apt-get upgrade --yes && apt clean --yes && \
    rm -rf /var/lib/apt/lists/*

# Source code build
FROM deps as build
ARG LLVM_VERSION

WORKDIR /remill
COPY ./ ./

RUN git config --global user.email "41898282+github-actions[bot]@users.noreply.github.com" && git config --global user.name "github-actions[bot]"

RUN ./scripts/build.sh \
    --llvm-version ${LLVM_VERSION} \
    --prefix /opt/trailofbits \
    --extra-cmake-args "-DCMAKE_BUILD_TYPE=Release" \
    --disable-package

RUN pip3 install ./scripts/diff_tester_export_insns

RUN cd remill-build && \
    cmake --build . --target test_dependencies -- -j $(nproc) && \
    # CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --verbose --target test -- -j $(nproc) && \
    cmake --build . --target install

# Small installation image
FROM base as install
ARG LLVM_VERSION

COPY --from=build /opt/trailofbits /opt/trailofbits
COPY scripts/docker-lifter-entrypoint.sh /opt/trailofbits
ENV LLVM_VERSION=llvm${LLVM_VERSION} \
    PATH=/opt/trailofbits/bin
ENTRYPOINT ["/opt/trailofbits/docker-lifter-entrypoint.sh"]
