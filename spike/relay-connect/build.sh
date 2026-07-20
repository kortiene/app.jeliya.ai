#!/usr/bin/env bash
# THROWAWAY Phase 0 spike (#23) — build script.
#
# Builds the four spike components:
#   1. native-endpoint  (Rust binary, release)
#   2. relay-auth       (Rust binary, release)
#   3. relay-server     (Rust binary, release)
#   4. browser-client   (wasm cdylib, wasm32-unknown-unknown via wasm-pack)
#
# Then copies the wasm pkg into web/pkg/ so the static page can import it.
#
# Nothing here touches the Jeliya workspace: the spike has its own
# Cargo.toml/Cargo.lock and is built from this directory only.
set -euo pipefail

cd "$(dirname "$0")"

# The wasm build needs clang (for ring's C/asm) and llvm-ar. On this box they
# live in a sysroot under /tmp and in the rustup toolchain respectively.
LLVM_BIN="/tmp/jeliya-sysroot/usr/lib/llvm-18/bin"
RUSTLIB_BIN="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | grep host | awk '{print $2}')/bin"
export PATH="${LLVM_BIN}:${RUSTLIB_BIN}:${PATH}"
export CC_wasm32_unknown_unknown=clang
export AR_wasm32_unknown_unknown=llvm-ar

echo "==> building native-endpoint, relay-auth, relay-server (release)…"
cargo build --release

echo "==> building browser-client (wasm32-unknown-unknown, wasm-pack --target web)…"
(cd browser-client && wasm-pack build --target web --release)

echo "==> staging wasm pkg into web/pkg/…"
rm -rf web/pkg
cp -r browser-client/pkg web/pkg

echo "==> done. Artifacts:"
ls -lh target/release/spike-native-endpoint target/release/spike-relay-auth target/release/spike-relay-server
ls -lh web/pkg/spike_browser_client_bg.wasm
