#!/usr/bin/env bash
# Build NSS (pinned release, with the NSPR it ships with) and the DTLS adapter into .build/nss/.
set -euo pipefail

VERSION=3.134
NSPR_VERSION=4.41
# Mozilla's combined release archive: tag NSS_3_134_RTM plus NSPR_4_41_RTM.
URL="https://ftp.mozilla.org/pub/security/nss/releases/NSS_3_134_RTM/src/nss-${VERSION}-with-nspr-${NSPR_VERSION}.tar.gz"
SHA256=d37c4871ec83d72f5b98450458d09eb57e068a0b148a7f7cf5f6fa928af9664f
# Upstream defaults apart from an optimised 64-bit build without the gtest suite.
MAKE_FLAGS=(BUILD_OPT=1 USE_64=1 NSS_DISABLE_GTESTS=1)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="$REPO_ROOT/.build/nss"
ARCHIVE="$PREFIX/dl/nss-${VERSION}-with-nspr-${NSPR_VERSION}.tar.gz"
SRC="$PREFIX/src/nss-${VERSION}"
INSTALL="$PREFIX/install"
STAMP="$INSTALL/.stamp"
STAMP_CONTENT="$SHA256 ${MAKE_FLAGS[*]}"

rm -f "$PREFIX/.built"
mkdir -p "$PREFIX/dl" "$PREFIX/bin"

if [[ ! -f "$STAMP" || "$(cat "$STAMP")" != "$STAMP_CONTENT" ]]; then
    if [[ ! -f "$ARCHIVE" ]] || ! echo "$SHA256  $ARCHIVE" | sha256sum --check --status; then
        curl -fsSL --retry 3 -o "$ARCHIVE.tmp" "$URL"
        mv "$ARCHIVE.tmp" "$ARCHIVE"
    fi
    if ! echo "$SHA256  $ARCHIVE" | sha256sum --check --status; then
        echo "checksum mismatch for $ARCHIVE (expected $SHA256)" >&2
        rm -f "$ARCHIVE"
        exit 1
    fi

    rm -rf "$PREFIX/src" "$INSTALL"
    mkdir -p "$PREFIX/src"
    tar -xzf "$ARCHIVE" -C "$PREFIX/src"
    grep -q "^#define NSS_VERSION \"$VERSION\" " "$SRC/nss/lib/nss/nss.h"
    grep -q "^#define PR_VERSION \"$NSPR_VERSION\"$" "$SRC/nspr/pr/include/prinit.h"
    if ! make -C "$SRC/nss" -j"$(nproc)" nss_build_all "${MAKE_FLAGS[@]}" >"$PREFIX/make.log" 2>&1; then
        tail -n 60 "$PREFIX/make.log" >&2
        exit 1
    fi
    # NSS installs nothing itself; dist/ holds symlinks into the source tree, hence -L.
    dist="$SRC/dist/$(cat "$SRC/dist/latest")"
    mkdir -p "$INSTALL/lib" "$INSTALL/include"
    cp -L "$dist"/lib/*.so "$dist"/lib/*.chk "$INSTALL/lib/"
    cp -rL "$SRC/dist/public/nss" "$INSTALL/include/nss"
    cp -rL "$dist/include" "$INSTALL/include/nspr"
    rm -rf "$PREFIX/src"
    echo "$STAMP_CONTENT" >"$STAMP"
fi

# The adapter is always rebuilt: it takes a second and the library stamp does not cover adapter.c.
# DT_RPATH (not RUNPATH) so the pinned libraries win over a system NSS for every dependency too.
cc -std=c11 -O2 -Wall -Wextra -Werror -I"$INSTALL/include/nss" -I"$INSTALL/include/nspr" \
    -o "$PREFIX/bin/nss-adapter" "$HERE/adapter.c" -L"$INSTALL/lib" \
    -Wl,--disable-new-dtags,-rpath,"$INSTALL/lib" \
    -lssl3 -lnss3 -lnssutil3 -lplc4 -lplds4 -lnspr4

# The runner reads the version from the first line of .built.
{
    echo "nss ${VERSION}"
    echo "nspr=${NSPR_VERSION}"
    echo "url=$URL"
    echo "sha256=$SHA256"
    echo "make_flags=${MAKE_FLAGS[*]}"
} >"$PREFIX/.built.tmp"
mv "$PREFIX/.built.tmp" "$PREFIX/.built"
