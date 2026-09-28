#!/usr/bin/env bash
# E-14's one command: build the verifier for a browser, check the fixtures, serve the page.
#
# D-124's condition was that the build's new dependency clear the licence gate. There is no new
# dependency: `tsc` already emits browser-shaped ES modules, and the only thing a browser cannot
# resolve is the three bare specifiers into `@noble/hashes` and `@noble/curves`. Both are plain ES
# modules whose internal imports are relative, so an import map with two prefix entries resolves the
# whole graph and this script's build step is a copy.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD=demo/build
PORT="${PORT:-8730}"

command -v node >/dev/null || { echo "demo: node is required (v24 or later)" >&2; exit 1; }

echo "----- the verifier's dependencies, from the committed lock file"
npm --prefix ts ci --silent

echo "----- the verifier, compiled for a browser"
rm -rf "$BUILD"
mkdir -p "$BUILD/vendor/@noble"
npx --prefix ts tsc -p ts/tsconfig.build.json --outDir "$BUILD/verifier"

echo "----- the two runtime dependencies, where an import map can reach them"
cp -R ts/node_modules/@noble/hashes "$BUILD/vendor/@noble/hashes"
cp -R ts/node_modules/@noble/curves "$BUILD/vendor/@noble/curves"

echo "----- the fixtures, against their manifest"
( cd demo/fixtures && shasum -a 256 -c <(awk '{print $1 "  " $3}' MANIFEST.sha256) )

echo "----- the demo's own tests"
node --test "demo/test/*.test.mjs"

echo
PORT="$PORT" node demo/serve.mjs
