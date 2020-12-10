ARG LLVM_VERSION=1000
ARG ARCH=amd64
ARG UBUNTU_VERSION=18.04
ARG DISTRO_BASE=ubuntu${UBUNTU_VERSION}
ARG BUILD_BASE=ubuntu:${UBUNTU_VERSION}
ARG LIBRARIES=/opt/trailofbits/libraries

# Run-time dependencies go here
FROM ${BUILD_BASE} as base

RUN apt-get update && \
    apt-get install -qqy --no-install-recommends libtinfo5 zlib1g libz3-4 && \
    rm -rf /var/lib/apt/lists/*


# Build-time dependencies go here
FROM trailofbits/cxx-common:llvm${LLVM_VERSION}-${DISTRO_BASE}-${ARCH} as deps

ENV DEBIAN_FRONTEND=noninteractive

RUN if [ "$(uname -m)" = "aarch64" ]; then dpkg --add-architecture armhf; fi && \
    apt-get update && \
    if [ "$(uname -m)" = "x86_64" ]; then apt-get install -qqy gcc-multilib g++-multilib; fi && \
    if [ "$(uname -m)" = "aarch64" ]; then apt-get install -qqy gcc-arm-linux-gnueabihf libstdc++-8-dev:armhf; fi && \
    apt-get install -qqy zlib1g-dev libz3-4 ninja-build ccache git python3 curl coreutils build-essential libtinfo-dev lsb-release && \
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

RUN mkdir build && cd build && \
    cmake -G Ninja -DCMAKE_VERBOSE_MAKEFILE=True -DCMAKE_INSTALL_PREFIX=/opt/trailofbits/remill .. && \
    cmake --build . --target install

RUN cd build && \
    cmake --build . --target test_dependencies && \
    env CTEST_OUTPUT_ON_FAILURE=1 cmake --build . --target test


FROM base as dist
ARG LLVM_VERSION

COPY scripts/docker-lifter-entrypoint.sh /opt/trailofbits/remill/docker-lifter-entrypoint.sh
COPY --from=build /opt/trailofbits/remill /opt/trailofbits/remill
ENV PATH=/opt/trailofbits/remill/bin:${PATH} \
    LLVM_VERSION=llvm${LLVM_VERSION}
ENTRYPOINT ["/opt/trailofbits/remill/docker-lifter-entrypoint.sh"]
