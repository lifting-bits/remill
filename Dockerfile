ARG LLVM_VERSION=10
# TODO: Untested for anything other than amd64 images
# ARG ARCH=amd64
ARG DISTRO_TAG=18.04
ARG DISTRO=ubuntu
# Used for small final dist image. Shouldn't require any run-time dependencies
# if we do everything correctly, since it's all statically linked.
ARG DISTRO_BASE=${DISTRO}:${DISTRO_TAG}
# Used for pulling in build dependencies
ARG BUILD_BASE=trailofbits/cxx-common/vcpkg-builder-${DISTRO}:${DISTRO_TAG}

# Run-time dependencies go here
FROM ${BUILD_BASE} as base

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -qqy --no-install-recommends pixz xz-utils make && \
    rm -rf /var/lib/apt/lists/*


# Source code build
FROM base as build
ARG LLVM_VERSION

WORKDIR /projects/remill
COPY . ./

RUN ./scripts/build.sh --prefix /opt/lifting-bits --llvm-version ${LLVM_VERSION}
WORKDIR remill-build
RUN cmake --build . --target install -- -j "$(nproc)"


FROM ${DISTRO_BASE} as dist
ARG LLVM_VERSION
COPY scripts/docker-lifter-entrypoint.sh /opt/lifting-bits/share/remill/docker-lifter-entrypoint.sh
COPY --from=build /opt/lifting-bits/bin /opt/lifting-bits/bin
COPY --from=build /opt/lifting-bits/share /opt/lifting-bits/share
ENV PATH="/opt/lifting-bits/bin:${PATH}" \
    LLVM_VERSION="llvm${LLVM_VERSION}"
ENTRYPOINT ["/opt/lifting-bits/share/remill/docker-lifter-entrypoint.sh"]
