#!/usr/bin/env bash
#
# Build the release binaries and package the distributable bundle.
#
# The Release workflow calls this, so a bundle built here is the same bundle a
# pushed tag publishes. Run it before tagging to check what the tag would ship.
#
#   scripts/build-release.sh [VERSION]
#
# VERSION defaults to `git describe` (e.g. v1.0.0, or v1.0.0-3-gabc1234-dirty
# on an untagged working tree). Output:
#
#   dist/<pkg>/            unpacked bundle
#   dist/<pkg>.tar.gz      archive
#   dist/<pkg>.tar.gz.sha256

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

err() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; }
log() { printf '\033[36m==>\033[0m %s\n' "$*"; }

VERSION="${1:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"

# ubuntu-22.04 runners report linux/x86_64, so CI keeps naming its archives
# tron-node-<tag>-linux-x86_64 without special-casing.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
PKG="tron-node-${VERSION}-${OS}-${ARCH}"

# Every binary the bundle ships. tron-snapshot-convert lives in its own crate
# so its LevelDB reader never links into the node — which is exactly why it
# ships as a separate binary here: importing a java-tron snapshot is the
# supported way to bootstrap, and a downloaded bundle has no cargo to build it.
#
# Deliberately NOT shipped: rig_probe, vote_audit (tron-node) and
# extract_sapling_vk (tron-tvm) are one-off divergence-hunting and build-time
# tools; `tron-node diag` covers the operator-facing diagnostics.
BINARIES=(
  tron-node
  tron-wallet
  tron-replay
  tron-state-diff
  tron-snapshot-convert
  tron-firehose-postgres
  tron-firehose-nats
  tron-firehose-clickhouse
)

# Development tooling that stays out of the bundle; everything else in
# scripts/ ships.
BUNDLE_SCRIPT_EXCLUDE=(build-release.sh)

preflight() {
  local missing=()
  command -v cargo >/dev/null || missing+=("cargo (https://rustup.rs)")
  command -v protoc >/dev/null || missing+=("protoc (tron-proto's build script needs >=3.15 for proto3 optional)")
  command -v strip >/dev/null || missing+=("strip (binutils)")
  if ((${#missing[@]})); then
    err "missing build prerequisites:"
    printf '  - %s\n' "${missing[@]}" >&2
    exit 1
  fi

  # librocksdb-sys dlopens libclang at build time (the bindgen-runtime
  # feature). clang-sys resolves it from LIBCLANG_PATH and a set of built-in
  # paths that this cannot faithfully reproduce, so a miss here is a hint,
  # not a verdict — cargo decides. Note the command substitution: piping
  # ldconfig into `grep -q` would SIGPIPE ldconfig and trip pipefail.
  local ldcache
  ldcache="$(ldconfig -p 2>/dev/null || true)"
  if [[ -z "${LIBCLANG_PATH:-}" && "$ldcache" != *libclang* ]]; then
    printf '\033[33mwarning:\033[0m libclang not found in the ldconfig cache.\n' >&2
    printf '         If the RocksDB build fails, install clang/libclang or set LIBCLANG_PATH.\n' >&2
  fi
}

build() {
  log "building ${#BINARIES[@]} release binaries (${VERSION})"
  local args=()
  for b in "${BINARIES[@]}"; do args+=(--bin "$b"); done
  cargo build --release "${args[@]}"
}

package() {
  local dest="dist/${PKG}"
  log "packaging ${PKG}"
  rm -rf "$dest"
  mkdir -p "$dest/scripts" "$dest/docs"

  # Binaries land at the bundle root so the bundled try.sh finds tron-node
  # next to itself with no build step.
  for b in "${BINARIES[@]}"; do
    install -m 0755 "target/release/${b}" "$dest/"
    strip "$dest/${b}"
  done

  # LICENSE is the LGPL, which is written as a set of additional permissions
  # on top of the GPL and incorporates it by reference — so the GPL text has
  # to ship alongside it for the terms to be complete.
  install -m 0644 config.example.toml goblin.svg README.md LICENSE LICENSE.GPL "$dest/"
  install -m 0755 try.sh "$dest/"

  local skip
  for s in scripts/*.sh; do
    skip=""
    for x in "${BUNDLE_SCRIPT_EXCLUDE[@]}"; do
      [[ "$(basename "$s")" == "$x" ]] && skip=1 && break
    done
    [[ -n "$skip" ]] || install -m 0755 "$s" "$dest/scripts/"
  done

  cp -r docs/. "$dest/docs/"

  tar -C dist -czf "dist/${PKG}.tar.gz" "${PKG}"
  ( cd dist && sha256sum "${PKG}.tar.gz" > "${PKG}.tar.gz.sha256" )
}

preflight
build
package

log "bundle:  dist/${PKG}.tar.gz ($(du -h "dist/${PKG}.tar.gz" | cut -f1))"
log "sha256:  $(cut -d' ' -f1 < "dist/${PKG}.tar.gz.sha256")"
