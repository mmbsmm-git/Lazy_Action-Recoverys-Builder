# Ubuntu 20.04 container with all Android 9 / OrangeFox build deps pre-installed.
# Pre-built once and pushed to GHCR, so workflow runs skip apt install entirely.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# All deps that Android 9 (OFRP 9.0) build needs on Ubuntu 20.04.
# NOTE: on focal(20.04) the 32-bit ncurses package is lib32ncurses-dev,
# NOT lib32ncurses5 (which only exists on 16.04/18.04).
# Packages are split into two RUNs; the legacy ones must succeed, the rest are
# allowed to fail (|| true) so a bad package name doesn't kill the whole image.
RUN apt-get update -y && apt-get install -y \
    git aria2 python2.7 python-is-python2 \
    libncurses5 libtinfo5 lib32ncurses-dev \
    libc6-dev-i386 \
    build-essential flex bison gperf zip curl zlib1g-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Extra 32-bit / multilib host-tool deps (best-effort)
RUN apt-get update -y && apt-get install -y \
    lib32z1 lib32z1-dev lib32stdc++6 lib32readline-dev \
    gcc-multilib g++-multilib \
    x11proto-core-dev libx11-dev libgl1-mesa-dev libxml2-utils xsltproc unzip \
    || true

# repo tool: Android source sync needs the `repo` command (not an apt package).
# Install Google's repo launcher script. Must succeed (repo is required by sync).
RUN curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo -o /usr/local/bin/repo && \
    chmod a+x /usr/local/bin/repo && \
    head -1 /usr/local/bin/repo && \
    repo --version

# sanity check
RUN python2 --version && \
    ldconfig -p | grep -E 'lib(tinfo|ncurses)5\.so' | head

WORKDIR /workspace
CMD ["/bin/bash"]
