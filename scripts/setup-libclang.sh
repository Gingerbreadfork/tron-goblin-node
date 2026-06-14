#!/usr/bin/env bash
# Create a `libclang.so` (or `.dylib`) symlink under `.cargo/libclang-shim/`
# so clang-sys can find it on systems that only ship the versioned
# `libclang.so.<ver>` filename (Fedora, RHEL, Arch w/o `clang` meta-pkg).
#
# clang-sys is pulled in transitively by `rocksdb` → `librocksdb-sys` →
# `bindgen`. Its build script literally globs for `libclang.so` and
# `libclang-*.so`, which doesn't match the versioned `.so.21.1` form
# that ships on most distros.
#
# `.cargo/config.toml` points `LIBCLANG_PATH` at the shim dir created
# below (relative to the config file), so once this script runs the
# whole workspace builds without further env vars.
#
# Idempotent — safe to re-run. Pick the highest-versioned `libclang`
# found so a system upgrade doesn't strand the symlink on an old file.

set -euo pipefail

SHIM_DIR=".cargo/libclang-shim"

mkdir -p "$SHIM_DIR"

# If the caller already knows where libclang lives, respect that first.
if [[ -n "${LIBCLANG_PATH:-}" ]]; then
  if [[ -d "$LIBCLANG_PATH" ]]; then
    FOUND_LIBCLANG="$(find "$LIBCLANG_PATH" -maxdepth 1 \
      \( -name 'libclang.so' -o -name 'libclang.so.*' -o -name 'libclang.dylib' \) \
      2>/dev/null | sort -V | tail -n 1 || true)"
  elif [[ -f "$LIBCLANG_PATH" ]]; then
    FOUND_LIBCLANG="$LIBCLANG_PATH"
  else
    FOUND_LIBCLANG=""
  fi
else
  FOUND_LIBCLANG=""
fi

# Search common Linux and macOS install locations.
if [[ -z "$FOUND_LIBCLANG" ]]; then
  shopt -s nullglob

  SEARCH_DIRS=(
    /usr/lib64
    /usr/lib/x86_64-linux-gnu
    /usr/lib/aarch64-linux-gnu
    /usr/lib
    /usr/local/lib

    # Ubuntu/Debian GitHub Actions runners commonly install libclang here.
    /usr/lib/llvm-*/lib

    # Homebrew LLVM paths.
    /opt/homebrew/opt/llvm/lib
    /usr/local/opt/llvm/lib
  )

  FOUND_LIBCLANG="$(find "${SEARCH_DIRS[@]}" -maxdepth 1 \
    \( -name 'libclang.so' -o -name 'libclang.so.*' -o -name 'libclang.dylib' \) \
    2>/dev/null | sort -V | tail -n 1 || true)"
fi

if [[ -z "$FOUND_LIBCLANG" ]]; then
  cat >&2 <<'EOF'
ERROR: no libclang library found in standard system paths.

Install your platform's LLVM/clang development package, then re-run:

  Fedora / RHEL :  sudo dnf install clang-devel llvm-devel
  Ubuntu / Deb  :  sudo apt install libclang-dev llvm-dev
  Arch          :  sudo pacman -S clang
  macOS (brew)  :  brew install llvm

If you've already installed it, set LIBCLANG_PATH manually:

  export LIBCLANG_PATH=/path/to/dir/containing/libclang.so
  export LIBCLANG_PATH=/path/to/libclang.so
EOF
  exit 1
fi

rm -f "$SHIM_DIR/libclang.so" "$SHIM_DIR/libclang.dylib"

case "$FOUND_LIBCLANG" in
  *.dylib)
    ln -s "$FOUND_LIBCLANG" "$SHIM_DIR/libclang.dylib"
    ;;
  *)
    ln -s "$FOUND_LIBCLANG" "$SHIM_DIR/libclang.so"
    ;;
esac

echo "libclang shim created:"
echo "  $SHIM_DIR -> $FOUND_LIBCLANG"
