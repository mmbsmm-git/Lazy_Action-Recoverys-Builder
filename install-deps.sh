#!/bin/bash
# Fault-tolerant dependency installer for the Ubuntu 20.04 OFRP build image.
# Installs packages ONE BY ONE; a failing package is recorded and skipped so the
# rest still install. At the end, all missing packages are listed.
# CORE packages must all succeed (image build fails otherwise).
# OPTIONAL packages may fail (only reported).

set -u
export DEBIAN_FRONTEND=noninteractive

FAILED=()
MISSING_CORE=0

install_one() {
  local pkg="$1" kind="$2"
  if apt-get install -y --no-install-recommends "$pkg" >/dev/null 2>&1; then
    echo "[OK]    $pkg ($kind)"
  else
    echo "[FAIL]  $pkg ($kind)"
    FAILED+=("$pkg:$kind")
    if [ "$kind" = "core" ]; then MISSING_CORE=1; fi
  fi
}

echo "== apt update =="
apt-get update -y

# ---- CORE (must all succeed) ----
echo "== Installing CORE packages =="
CORE_PKGS="
git aria2 python2.7 python-is-python2 python3 rsync
libncurses5 libtinfo5
build-essential flex bison gperf zip curl zlib1g-dev ca-certificates
gnupg m4 bc cpio lz4 liblz4-tool xz-utils lzop
imagemagick pngcrush schedtool squashfs-tools ccache
"
for p in $CORE_PKGS; do install_one "$p" core; done

# ---- OPTIONAL (may fail, only reported) ----
echo "== Installing OPTIONAL packages =="
OPT_PKGS="
lib32ncurses-dev libc6-dev-i386 lib32z1 lib32z1-dev lib32stdc++6 lib32readline-dev
gcc-multilib g++-multilib
x11proto-core-dev libx11-dev libgl1-mesa-dev libxml2-utils xsltproc unzip fontconfig
"
for p in $OPT_PKGS; do install_one "$p" opt; done

# ---- repo tool (required by sync) ----
echo "== Installing repo =="
if curl -fsSL https://storage.googleapis.com/git-repo-downloads/repo -o /usr/local/bin/repo; then
  chmod a+x /usr/local/bin/repo
  echo "[OK]    repo (core)"
else
  echo "[FAIL]  repo (core)"
  MISSING_CORE=1
fi

# ---- Report ----
echo ""
echo "=========================================="
echo " INSTALL SUMMARY"
echo "=========================================="
if [ ${#FAILED[@]} -eq 0 ]; then
  echo " All packages installed successfully."
else
  echo " The following packages could NOT be installed:"
  for f in "${FAILED[@]}"; do echo "   - $f"; done
fi
echo "=========================================="

# CORE missing -> build fails so we don't cache a broken image
if [ "$MISSING_CORE" = "1" ]; then
  echo "ERROR: one or more CORE packages failed. Image build aborted."
  exit 1
fi

echo "Done. (Optional failures above are non-fatal.)"
exit 0
