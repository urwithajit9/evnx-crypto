#!/usr/bin/env bash
#
# Build the browser package published to npm as @evnx/crypto-wasm.
#
# The dashboard at app.evnx.dev consumes this. It is the *same Rust* the CLI and
# the server link against — which is the entire reason this crate is separate.
# Two implementations of one protocol drift, and the symptom is a blob one client
# wrote that the other cannot open.
#
#   ./scripts/build-wasm.sh             # build into pkg/
#   ./scripts/build-wasm.sh --publish   # build, then npm publish
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

PKG_NAME="@evnx/crypto-wasm"
OUT_DIR="pkg"

command -v wasm-pack >/dev/null || {
    echo "error: wasm-pack not installed — cargo install wasm-pack" >&2; exit 1; }

rustup target list --installed | grep -q wasm32-unknown-unknown || {
    echo "error: wasm32 target missing — rustup target add wasm32-unknown-unknown" >&2; exit 1; }

echo "==> building $PKG_NAME"
# --target web, not bundler: the dashboard loads this inside a Web Worker with a
# plain ES import plus an explicit init(), which is the shape `web` produces.
wasm-pack build --target web --out-dir "$OUT_DIR" --release --features wasm

# wasm-pack names the package after the crate (evnx-crypto). The npm package is
# @evnx/crypto-wasm — scoped, and suffixed so it can never be mistaken for a
# JavaScript reimplementation of the crate.
echo "==> rewriting package metadata"
node - "$OUT_DIR" "$PKG_NAME" <<'NODE'
const fs = require('fs');
const [dir, name] = process.argv.slice(2);
const p = `${dir}/package.json`;
const pkg = JSON.parse(fs.readFileSync(p, 'utf8'));

pkg.name = name;
pkg.description =
  'Zero-knowledge encryption primitives for evnx, compiled to WebAssembly. ' +
  'The same Rust the evnx CLI and server use — Argon2id, AES-256-GCM, ' +
  'XChaCha20-Poly1305, X25519 and SRP-6a. Keys are opaque handles, never bytes.';
pkg.publishConfig = { access: 'public' };
pkg.sideEffects = ['./snippets/*', '*.wasm'];
pkg.keywords = [
  'evnx', 'wasm', 'webassembly', 'cryptography',
  'zero-knowledge', 'argon2', 'srp', 'dotenv',
];

fs.writeFileSync(p, JSON.stringify(pkg, null, 2) + '\n');
console.log(`    name    -> ${pkg.name}`);
console.log(`    version -> ${pkg.version}`);
NODE

RAW=$(stat -c%s "$OUT_DIR"/*_bg.wasm)
GZ=$(gzip -9 -c "$OUT_DIR"/*_bg.wasm | wc -c)
echo "==> wasm: ${RAW} bytes raw, ${GZ} bytes gzipped"

if [ "${1:-}" = "--publish" ]; then
    # Check auth BEFORE attempting the publish. This script does not manage npm
    # credentials and deliberately never asks for one — `npm publish` reads them
    # from ~/.npmrc (written by `npm login`) or from NODE_AUTH_TOKEN.
    #
    # Without this check the failure surfaces as npm's ENEEDAUTH after a full
    # build, or worse as a 404 — npm answers 404 rather than 403 for an
    # unauthorised publish, so it reads like the package does not exist.
    if ! npm whoami >/dev/null 2>&1; then
        cat >&2 <<'MSG'
error: not authenticated to npm.

  Interactive:   npm login
  Or with a token, WITHOUT writing it to disk:
                 NODE_AUTH_TOKEN=<token> ./scripts/build-wasm.sh --publish

  The token needs read-write on the @evnx scope. Note that npm reports an
  unauthorised publish as 404, not 403, so a permissions problem looks like a
  missing package.
MSG
        exit 1
    fi
    echo "==> publishing as $(npm whoami)"
    ( cd "$OUT_DIR" && npm publish --access public )
else
    echo "==> built. Publish with:  (cd $OUT_DIR && npm publish --access public)"
fi
