# Ubuntu 20.04 container with all Android 9 / OrangeFox build deps pre-installed.
# Pre-built once and pushed to GHCR; workflows then pull it (deps are "in the
# repo's container registry"), so subsequent runs skip all installation.
#
# Deps are installed by install-deps.sh: one-by-one, a failure is recorded and
# skipped so the rest still install; all missing packages are listed at the end.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Copy the fault-tolerant installer and run it.
COPY install-deps.sh /tmp/install-deps.sh
RUN bash /tmp/install-deps.sh && rm -f /tmp/install-deps.sh

# sanity check (python2 for Android 9 build, python3 for repo; repo --version is best-effort)
RUN python2 --version && \
    python3 --version && \
    ldconfig -p | grep -E 'lib(tinfo|ncurses)5\.so' | head && \
    (repo --version || echo "repo version check skipped")

WORKDIR /workspace
CMD ["/bin/bash"]
