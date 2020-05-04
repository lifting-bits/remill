ARG LLVM_VERSION=800
ARG ARCH=amd64
ARG BOOTSTRAP=/opt/trailofbits/bootstrap
ARG LIBRARIES=/opt/trailofbits/libraries
ARG REMILL_INSTALL=/opt/trailofbits/remill
ARG DISTRO_BASE=ubuntu18.04

#FROM trailofbits/cxx-common/llvm${LLVM_VERSION}-${DISTRO_BASE}-${arch}:latest as base
FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as base
ARG BOOTSTRAP
ARG LIBRARIES
ARG LLVM_VERSION
ARG REMILL_INSTALL

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    if [ "$(uname -m)" = "x86_64" ]; then apt-get install -qqy gcc-multilib g++-multilib; fi && \
    apt-get install -qqy ninja-build git python2.7 curl coreutils build-essential libtinfo-dev lsb-release && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /remill
WORKDIR /remill
COPY . ./

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}"
ENV CC="${LIBRARIES}/llvm/bin/clang"
ENV CXX="${LIBRARIES}/llvm/bin/clang++"
ENV TRAILOFBITS_LIBRARIES="${LIBRARIES}"

RUN mkdir /remill/build && cd /remill/build && \
    cmake -G Ninja -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=${REMILL_INSTALL} .. && \
    cmake --build . --target install

ENTRYPOINT ["/bin/bash"]
