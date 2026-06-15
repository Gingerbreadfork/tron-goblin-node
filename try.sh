#!/usr/bin/env bash
#
# try.sh — the TRON Goblin live mainnet feed.
#
# One command, and within seconds you're watching the REAL TRON mainnet live:
# blocks landing every ~3s, hundreds of real transactions each, decoded and
# classified into a self-updating terminal dashboard — TRX moved, fees burned,
# USDT transfers, contract calls, tokens, the busiest block, live TPS. No
# snapshot, no 100GB+ backfill, no hours of syncing.
#
# How it works: the node discovers the current chain tip over the real TRON
# peer-to-peer protocol (it asks live peers for their head), tells peers it's
# already there so they stream it the live block tail, and decodes every block
# for display only — never executed (there is no chain state). No HTTP, no
# external services: just the node and the network.
#
# Usage:
#   ./try.sh                      # follow the live mainnet tip
#   ./try.sh --peer HOST:18888    # also pin a specific p2p peer
#
set -euo pipefail

# --- pretty ----------------------------------------------------------------
if [ -t 1 ]; then
  BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[1;31m'; GRN=$'\033[1;32m'
  YEL=$'\033[1;33m'; CYN=$'\033[1;36m'; RST=$'\033[0m'
else
  BOLD=""; DIM=""; RED=""; GRN=""; YEL=""; CYN=""; RST=""
fi
say()  { printf '%s%s%s\n' "$CYN" "$*" "$RST"; }
ok()   { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }
warn() { printf '%s%s%s\n' "$YEL" "$*" "$RST"; }
err()  { printf '%s%s%s\n' "$RED" "$*" "$RST" >&2; }

# --- config ----------------------------------------------------------------
RPC_PORT=8190
PEER=""

while [ $# -gt 0 ]; do
  case "$1" in
    --peer) shift; PEER="${1:-}"; [ -n "$PEER" ] || { err "--peer needs HOST:PORT"; exit 2; } ;;
    --rpc-port) shift; RPC_PORT="${1:-}" ;;
    -h|--help) sed -n '3,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) err "unknown flag: $1 (try --help)"; exit 2 ;;
  esac
  shift
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate the node binary. Search order:
#   1. a `tron-node` sitting right next to this script — so the script + a
#      prebuilt binary can be dropped into any directory and "just work".
#   2. the usual cargo build output (target/release).
# If neither exists we fall back to building (only possible inside the repo).
BIN=""
for cand in "$SCRIPT_DIR/tron-node" "$SCRIPT_DIR/target/release/tron-node"; do
  if [ -x "$cand" ]; then BIN="$cand"; break; fi
done

# --- banner ----------------------------------------------------------------
printf '\n'
printf '%s  ┌────────────────────────────────────────────────────────────┐%s\n' "$RED" "$RST"
printf '%s  │   🧌  tron-goblin-node  ·  MAINNET LIVE FEED                │%s\n' "$RED" "$RST"
printf '%s  └────────────────────────────────────────────────────────────┘%s\n' "$RED" "$RST"
printf '%s  Real TRON mainnet, streaming into your terminal in seconds.%s\n\n' "$DIM" "$RST"

# --- resolve / build the binary --------------------------------------------
if [ -n "$BIN" ]; then
  say "using node binary: ${BIN/#$SCRIPT_DIR\//./}"
elif command -v cargo >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/Cargo.toml" ]; then
  say "no prebuilt binary found — building the node (release), first build takes a few minutes…"
  cargo build --release -p tron-node
  BIN="$SCRIPT_DIR/target/release/tron-node"
  [ -x "$BIN" ] || { err "build finished but $BIN is missing."; exit 1; }
  ok "build complete"
else
  err "no 'tron-node' binary found next to this script, and no cargo project to build one."
  err "drop a release build here as ./tron-node, or run this from the repo with cargo installed."
  exit 1
fi

# --- throwaway data dir ----------------------------------------------------
DATA_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tron-goblin-try.XXXXXX")"
LOG_FILE="$DATA_DIR/node.log"
NODE_PID=""
_CLEANED=0
cleanup() {
  # Run once: Ctrl-C fires the INT trap, then the shell exits and fires EXIT —
  # without this guard the teardown (and its message) would print twice.
  [ "$_CLEANED" = 1 ] && return
  _CLEANED=1
  printf '\033[?25h'  # restore cursor
  if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
    kill "$NODE_PID" 2>/dev/null || true
    for _ in $(seq 1 10); do kill -0 "$NODE_PID" 2>/dev/null || break; sleep 0.3; done
    kill -9 "$NODE_PID" 2>/dev/null || true
  fi
  rm -rf "$DATA_DIR" 2>/dev/null || true
  printf '\n%s  goblin out. 🧌  (temp data removed)%s\n' "$GRN" "$RST"
}
trap cleanup EXIT INT TERM

# --- launch ----------------------------------------------------------------
say "connecting to mainnet peers and discovering the live tip…"
sleep 1

# No seed list — the node finds peers via discovery (DNS tree + Kad DHT).
PEER_ARGS=()
[ -n "$PEER" ] && PEER_ARGS+=(--peer "$PEER")

# The dashboard renders on stdout; all logs go to stderr → the log file, so
# they never corrupt the dashboard. RUST_LOG kept quiet (warnings only).
RUST_LOG="${RUST_LOG:-warn}" TRON_LOG_FILE=off \
  "$BIN" start \
    --explore \
    ${PEER_ARGS[@]+"${PEER_ARGS[@]}"} \
    --data-dir "$DATA_DIR" \
    --rpc-port "$RPC_PORT" \
    --no-http --no-grpc --no-metrics \
    2>"$LOG_FILE" &
NODE_PID=$!

# Wait on the node; if it dies early, surface the log.
wait "$NODE_PID" 2>/dev/null || true
if [ -s "$LOG_FILE" ]; then
  tail_lines="$(tail -n 3 "$LOG_FILE" 2>/dev/null || true)"
  [ -n "$tail_lines" ] && { printf '%s' "$DIM"; echo "$tail_lines"; printf '%s' "$RST"; }
fi
