#!/bin/sh
set -eu

VERSION=1.8.1
COMMIT=e55dabd923ac8b54ee0573c1324783477850d75d
EMSDK=emscripten/emsdk:4.0.15
ROOT=$(cd -- "$(dirname -- "$0")/../.." >/dev/null 2>&1 && pwd)
WORK=$(mktemp -d /tmp/ctf-bkcrack.XXXXXX)

printf 'Fetching bkcrack %s...\n' "$VERSION"
SOURCE="$WORK/source"
git clone --quiet --no-checkout --filter=blob:none https://github.com/kimci86/bkcrack.git "$SOURCE"
git -C "$SOURCE" checkout --quiet "$COMMIT"
OUTPUT="$ROOT/src/runtimes/bkcrack"
mkdir -p "$OUTPUT"
mkdir -p "$WORK/build"

printf 'Configuring Emscripten build...\n'
docker run --rm --platform linux/amd64 \
  -v "$SOURCE:/src:ro" \
  -v "$ROOT/tools/bkcrack:/adapter:ro" \
  -v "$WORK/build:/build" \
  -v "$OUTPUT:/out" \
  "$EMSDK" emcmake cmake -S /adapter -B /build -DCMAKE_BUILD_TYPE=Release -DBKCRACK_SOURCE=/src

printf 'Compiling WASM pack...\n'
docker run --rm --platform linux/amd64 \
  -v "$SOURCE:/src:ro" \
  -v "$ROOT/tools/bkcrack:/adapter:ro" \
  -v "$WORK/build:/build" \
  -v "$OUTPUT:/out" \
  "$EMSDK" cmake --build /build --config Release -j1

printf 'Built bkcrack %s (%s) with %s; temporary build files: %s\n' "$VERSION" "$COMMIT" "$EMSDK" "$WORK"