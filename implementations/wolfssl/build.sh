#!/usr/bin/env bash
# Build wolfSSL (pinned release) and the adapter into .build/wolfssl/.
set -euo pipefail

VERSION=5.9.4
# Release archive from wolfssl.com: same sources as tag v5.9.4-stable, plus a generated configure.
URL="https://www.wolfssl.com/wolfssl-${VERSION}.zip"
SHA256=9cd0d69d208d025b16836c177658cc0deebc2a85c4b60898c9bc546bc6cbdf18

# Everything else is the upstream default; see implementations/wolfssl/README.md for each flag.
CONFIGURE_FLAGS=(
    --enable-dtls13
    --enable-dtls-mtu
    --enable-curve25519
    --enable-static
    --disable-shared
    --disable-examples
    --disable-crypttests
    --disable-benchmark
)
# Compiles in the logging code (off at runtime unless the adapter turns it on); keeps -O2.
LIB_CPPFLAGS="-DDEBUG_WOLFSSL"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"
PREFIX="$REPO_ROOT/.build/wolfssl"
ARCHIVE="$PREFIX/dl/wolfssl-${VERSION}.zip"
SRC="$PREFIX/src/wolfssl-${VERSION}"
INSTALL="$PREFIX/install"
STAMP="$INSTALL/.stamp"
STAMP_CONTENT="$SHA256 ${CONFIGURE_FLAGS[*]} CPPFLAGS=$LIB_CPPFLAGS"

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
    unzip -q "$ARCHIVE" -d "$PREFIX/src"
    (
        cd "$SRC"
        ./configure --prefix="$INSTALL" "${CONFIGURE_FLAGS[@]}" CPPFLAGS="$LIB_CPPFLAGS" \
            > "$PREFIX/configure.log"
        make -j"$(nproc)" > "$PREFIX/make.log"
        make install > "$PREFIX/install.log"
    )
    echo "$STAMP_CONTENT" > "$STAMP"
fi

# The adapter is always rebuilt: the CI cache key covers only build.sh and patches.
cc -std=c11 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L \
    -I"$INSTALL/include" -o "$PREFIX/bin/wolfssl-adapter" "$HERE/adapter.c" \
    "$INSTALL/lib/libwolfssl.a" -lm -lpthread

# The runner reads the version from the first line of .built.
{
    echo "wolfssl v${VERSION}-stable"
    echo "url=$URL"
    echo "sha256=$SHA256"
    echo "configure_flags=${CONFIGURE_FLAGS[*]}"
    echo "cppflags=$LIB_CPPFLAGS"
} > "$PREFIX/.built.tmp"
mv "$PREFIX/.built.tmp" "$PREFIX/.built"
