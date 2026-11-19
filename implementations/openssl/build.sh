#!/usr/bin/env bash
# Build OpenSSL 4.1.0 (static) and the DTLS adapter into .build/openssl/.
set -euo pipefail

VERSION=4.1.0
TARBALL=openssl-${VERSION}.tar.gz
URL=https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/${TARBALL}
SHA256=50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd
CONFIGURE_FLAGS=(no-shared no-docs no-tests)

IMPL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$IMPL_DIR/../.." && pwd)
OUT=$REPO_ROOT/.build/openssl
PREFIX=$OUT/install
# Any change to version or flags invalidates the installed library.
STAMP="$VERSION $SHA256 ${CONFIGURE_FLAGS[*]}"

mkdir -p "$OUT"
rm -f "$OUT/.built"

if [ "$(cat "$PREFIX/.stamp" 2>/dev/null)" != "$STAMP" ]; then
    rm -rf "$PREFIX" "$OUT/src"
    mkdir -p "$OUT/src"
    curl -fsSL --retry 3 -o "$OUT/src/$TARBALL" "$URL"
    echo "$SHA256  $OUT/src/$TARBALL" | sha256sum -c -
    tar -xzf "$OUT/src/$TARBALL" -C "$OUT/src"
    (
        cd "$OUT/src/openssl-$VERSION"
        ./Configure "${CONFIGURE_FLAGS[@]}" --prefix="$PREFIX" --openssldir="$PREFIX/ssl" --libdir=lib
        make -j"$(nproc)" >/dev/null
        make install_sw >/dev/null
    )
    rm -rf "$OUT/src"
    echo "$STAMP" >"$PREFIX/.stamp"
fi

# The adapter is rebuilt every time: the CI cache key covers build.sh, not adapter.c.
mkdir -p "$OUT/bin"
cc -std=c11 -O2 -Wall -Wextra -Werror -I"$PREFIX/include" \
    -o "$OUT/bin/dtls-adapter" "$IMPL_DIR/adapter.c" \
    "$PREFIX/lib/libssl.a" "$PREFIX/lib/libcrypto.a" -lpthread -ldl

"$PREFIX/bin/openssl" version >&2
# The runner reads the pinned version from the first line.
printf 'openssl %s\nconfigure: %s\n' "$VERSION" "${CONFIGURE_FLAGS[*]}" >"$OUT/.built"
