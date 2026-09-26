# Ubuntu 20.04 container with all Android 9 / OrangeFox build deps pre-installed.
# Pre-built once and pushed to GHCR, so workflow runs skip apt install entirely.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# All deps that Android 9 (OFRP 9.0) build needs on Ubuntu 20.04:
#  - python2.7 + python-is-python2 (build scripts need python2)
#  - libncurses5 / libtinfo5  (old clang / header-abi-dumper)
#  - 32-bit libs (lib32ncurses5, lib32z1, lib32stdc++6, libc6-dev-i386)
#  - standard AOSP host build deps
RUN apt-get update -y && apt-get install -y \
    git aria2 python2.7 python-is-python2 \
    libncurses5 libtinfo5 lib32ncurses5 lib32z1 lib32stdc++6 libc6-dev-i386 \
    build-essential flex bison gperf zip curl zlib1g-dev \
    x11proto-core-dev libx11-dev libgl1-mesa-dev libxml2-utils xsltproc unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# sanity check
RUN python2 --version && \
    ldconfig -p | grep -E 'lib(tinfo|ncurses)5\.so' | head

WORKDIR /workspace
CMD ["/bin/bash"]
