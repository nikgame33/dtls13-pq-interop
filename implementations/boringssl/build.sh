#!/usr/bin/env bash
# Build BoringSSL (pinned commit, static) and the DTLS adapter into .build/boringssl/.
set -euo pipefail

# BoringSSL has no releases; this is the tip of main on 2026-11-24 (committed 2026-11-24T09:02:32-08:00).
COMMIT=f3ba8e447de666b3820ab613f050b3bd6d1cb333
COMMIT_DATE=2026-11-24
REPO=https://boringssl.googlesource.com/boringssl
CMAKE_FLAGS=(-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF)

IMPL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$IMPL_DIR/../.." && pwd)
OUT=$REPO_ROOT/.build/boringssl
PREFIX=$OUT/install
SRC=$OUT/src
# Any change to commit or flags invalidates the installed library.
STAMP="$COMMIT ${CMAKE_FLAGS[*]}"

mkdir -p "$OUT"
rm -f "$OUT/.built"

if [ "$(cat "$PREFIX/.stamp" 2>/dev/null)" != "$STAMP" ]; then
    rm -rf "$PREFIX" "$SRC"
    mkdir -p "$SRC"
    git -C "$SRC" init -q
    git -C "$SRC" fetch -q --depth 1 "$REPO" "$COMMIT"
    git -C "$SRC" -c advice.detachedHead=false checkout -q FETCH_HEAD
    if [ "$(git -C "$SRC" rev-parse HEAD)" != "$COMMIT" ]; then
        echo "fetched commit does not match $COMMIT" >&2
        exit 1
    fi
    # The pregenerated sources in gen/ mean neither Go nor Perl is needed for the library.
    cmake -S "$SRC" -B "$SRC/build" "${CMAKE_FLAGS[@]}" >"$OUT/cmake.log"
    cmake --build "$SRC/build" --target ssl crypto -j"$(nproc)" >"$OUT/make.log"
    mkdir -p "$PREFIX/lib"
    cp -R "$SRC/include" "$PREFIX/include"
    cp "$SRC/build/libssl.a" "$SRC/build/libcrypto.a" "$PREFIX/lib/"
    rm -rf "$SRC"
    echo "$STAMP" >"$PREFIX/.stamp"
fi

# The adapter is rebuilt every time: the CI cache key covers build.sh, not adapter.c.
mkdir -p "$OUT/bin"
cc -std=c11 -O2 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -DBSSL_COMMIT="\"$COMMIT\"" \
    -I"$PREFIX/include" \
    -o "$OUT/bin/dtls-adapter" "$IMPL_DIR/adapter.c" \
    "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -lstdc++ -lpthread

# The runner reads the pinned version from the first line.
printf 'boringssl %s\ncommit_date=%s\nrepo=%s\ncmake_flags=%s\n' \
    "$COMMIT" "$COMMIT_DATE" "$REPO" "${CMAKE_FLAGS[*]}" >"$OUT/.built.tmp"
mv "$OUT/.built.tmp" "$OUT/.built"
