ARG LLVM_VERSION=800
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits/libraries

# Run-time dependencies go here
FROM ${BUILD_BASE} as base

RUN apt-get update && \
    apt-get install -qqy libtinfo5 && \
    rm -rf /var/lib/apt/lists/*


# Build-time dependencies go here
# FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as base
FROM ek-cxx-common as deps
ARG LIBRARIES

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    if [ "$(uname -m)" = "x86_64" ]; then apt-get install -qqy gcc-multilib g++-multilib; fi && \
    apt-get install -qqy ninja-build git python3 curl coreutils build-essential libtinfo-dev lsb-release && \
    rm -rf /var/lib/apt/lists/*


# Source code build
FROM deps as build
ARG LIBRARIES

WORKDIR /remill
COPY . ./

ENV PATH="${LIBRARIES}/llvm/bin:${LIBRARIES}/cmake/bin:${LIBRARIES}/protobuf/bin:${PATH}"
ENV CC="${LIBRARIES}/llvm/bin/clang"
ENV CXX="${LIBRARIES}/llvm/bin/clang++"
ENV TRAILOFBITS_LIBRARIES="${LIBRARIES}"

RUN mkdir /remill/build && cd /remill/build && \
    cmake -G Ninja -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=/opt/trailofbits/remill .. && \
    cmake --build . --target install


FROM base as dist

COPY --from=build /opt/trailofbits/remill /opt/trailofbits/remill
