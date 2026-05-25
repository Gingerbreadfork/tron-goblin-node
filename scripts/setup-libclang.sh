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

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
shim_dir="$repo_root/.cargo/libclang-shim"
mkdir -p "$shim_dir"

# Search common per-distro locations. macOS path included so the same
# script bootstraps an Apple-silicon homebrew install.
search_dirs=(
    /usr/lib64
    /usr/lib/x86_64-linux-gnu
    /usr/lib/aarch64-linux-gnu
    /usr/lib
    /usr/local/lib
    /opt/homebrew/opt/llvm/lib
    /usr/local/opt/llvm/lib
)

# Collect matches; `-cpp` excludes libclang-cpp (the C++ API lib) which
# clang-sys does not want. Sort -V picks the highest version last.
candidates=()
for dir in "${search_dirs[@]}"; do
    [ -d "$dir" ] || continue
    while IFS= read -r f; do
        candidates+=("$f")
    done < <(
        find "$dir" -maxdepth 1 \
             \( -name 'libclang.so' \
                -o -name 'libclang.so.*' \
                -o -name 'libclang.dylib' \) \
             ! -name '*-cpp*' \
             2>/dev/null | sort -V
    )
done

if [ ${#candidates[@]} -eq 0 ]; then
    cat <<'EOF' >&2
ERROR: no libclang library found in standard system paths.

Install your platform's LLVM/clang development package, then re-run:

  Fedora / RHEL :  sudo dnf install clang-devel llvm-devel
  Ubuntu / Deb  :  sudo apt install libclang-dev
  Arch          :  sudo pacman -S clang
  macOS (brew)  :  brew install llvm

If you've already installed it, set LIBCLANG_PATH manually:

  export LIBCLANG_PATH=/path/to/dir/containing/libclang.so
EOF
    exit 1
fi

# Last entry after `sort -V` is the highest version.
chosen="${candidates[$((${#candidates[@]} - 1))]}"

# Symlink name matches what clang-sys searches for on this OS.
case "$(uname -s)" in
    Darwin) link_name="libclang.dylib" ;;
    *)      link_name="libclang.so"   ;;
esac

ln -sfn "$chosen" "$shim_dir/$link_name"

echo "linked: $shim_dir/$link_name -> $chosen"
