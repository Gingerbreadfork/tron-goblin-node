#!/usr/bin/env bash
#
# bench/decode/ours.sh -- tron-goblin-node ("ours") side of the DECODE-throughput
# microbenchmark.
#
# Runs `tron-node bench-decode`, which loads the first --count blocks of the
# shared length-prefixed corpus into memory (untimed) and then, in a tight loop,
# decodes each Block protobuf, iterates its transactions, and decodes each
# contract's parameters (the production mempool/explore `decode_tx_summary`:
# protobuf-unpack the typed parameter + 4-byte selector -> method name + USDT ABI
# amount). No state, no RocksDB, no execution -- pure parse/decode CPU.
#
# It samples peak RSS of the decode process via lib.sh's bench_sample_proc and
# emits bench/results/decode-ours.json with the decode-dimension schema:
#
#   { "dimension":"decode", "engine":"ours", "version", "blocks", "txs",
#     "blocks_per_sec", "txs_per_sec", "peak_rss_mb", "notes" }
#
# The java counterpart (java.sh) decodes the EXACT same bytes with the same
# logical scope; bench/decode/README.md defines the apples-to-apples contract.
#
# The corpus comes from bench.config's BLOCKS_FILE (fetched by bootstrap.sh, or
# supplied by you). All paths come from bench/bench.config.
#
# USAGE
#   bench/decode/ours.sh [--count N] [--blocks FILE] [--out DIR]
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH_DIR="$(cd "$HERE/.." && pwd)"
export BENCH_DIR
REPO_ROOT="$(cd "$BENCH_DIR/.." && pwd)"
export REPO_ROOT
# shellcheck source=bench/lib.sh
source "$BENCH_DIR/lib.sh"
# shellcheck source=bench/bench.config
source "$BENCH_DIR/bench.config"

# ---- defaults (from config) -------------------------------------------------

COUNT="$DECODE_COUNT"
OUT="$RESULTS_DIR"
BLOCKS="$BLOCKS_FILE"

usage() {
  cat <<EOF
usage: bench/decode/ours.sh [--count N] [--blocks FILE] [--out DIR]

  --count N      number of leading corpus blocks to decode (default ${COUNT})
  --blocks FILE  shared length-prefixed .blocks corpus (default ${BLOCKS})
  --out DIR      results directory                       (default ${OUT})

Decode-only microbenchmark for the "ours" engine. Emits decode-ours.json.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --count)  COUNT="${2:?--count needs N}"; shift 2 ;;
    --blocks) BLOCKS="${2:?--blocks needs FILE}"; shift 2 ;;
    --out)    OUT="${2:?--out needs DIR}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ours.sh(decode): unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- guards -----------------------------------------------------------------

if [ ! -x "$TRON_NODE" ]; then
  echo "ours.sh(decode): $TRON_NODE not found or not executable." >&2
  echo "                 build it first: bench/bootstrap.sh --only node" >&2
  exit 1
fi
if [ ! -f "$BLOCKS" ]; then
  echo "ours.sh(decode): corpus not found: $BLOCKS" >&2
  echo "                 fetch it: bench/bootstrap.sh --only corpus, or set" >&2
  echo "                 BLOCKS_FILE / --blocks to a length-prefixed .blocks file." >&2
  exit 1
fi
if ! [ "$COUNT" -gt 0 ] 2>/dev/null; then
  echo "ours.sh(decode): --count must be a positive integer (got '$COUNT')." >&2
  exit 1
fi

mkdir -p "$OUT"
export BENCH_OUT_DIR="$OUT"

GIT_SHA="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
RUN_LOG="$OUT/decode-ours-${COUNT}.log"
SAMPLE_CSV="$OUT/decode-ours-${COUNT}.sample"
: > "$RUN_LOG"
: > "$SAMPLE_CSV"

echo "[decode-ours] corpus : $BLOCKS"
echo "[decode-ours] count  : $COUNT blocks"
echo "[decode-ours] binary : $TRON_NODE ($GIT_SHA)"

# ---- cleanup ----------------------------------------------------------------

ENGINE_PID=""
SAMPLER_PID=""
cleanup() {
  bench_stop_sampler "${SAMPLER_PID:-}"
  if [ -n "$ENGINE_PID" ] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    kill -TERM "$ENGINE_PID" 2>/dev/null
    wait "$ENGINE_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

# ---- run + sample -----------------------------------------------------------
#
# bench-decode prints the machine-parseable result line; tracing goes alongside.
# We capture both to the log and parse the result line afterwards. Peak RSS is
# sampled while it runs (the corpus load dominates residency).

RUST_LOG="${RUST_LOG:-info}" \
"$TRON_NODE" bench-decode --blocks "$BLOCKS" --count "$COUNT" \
  >"$RUN_LOG" 2>&1 &
ENGINE_PID=$!

SAMPLER_PID="$(bench_sample_proc "$ENGINE_PID" "$SAMPLE_CSV")" || SAMPLER_PID=""

wait "$ENGINE_PID" 2>/dev/null
RC=$?
ENGINE_PID=""
bench_stop_sampler "$SAMPLER_PID"
SAMPLER_PID=""

if [ "$RC" -ne 0 ]; then
  echo "ERROR: bench-decode exited rc=$RC; see $RUN_LOG" >&2
  tail -20 "$RUN_LOG" >&2
  exit 1
fi

# Parse "bench-decode: blocks=N txs=M elapsed_s=S blocks_per_sec=.. txs_per_sec=.."
RESULT_LINE="$(grep -E '^bench-decode: blocks=' "$RUN_LOG" | tail -1)"
if [ -z "$RESULT_LINE" ]; then
  echo "ERROR: did not find the bench-decode result line in $RUN_LOG" >&2
  tail -20 "$RUN_LOG" >&2
  exit 1
fi
echo "[decode-ours] $RESULT_LINE"

BLOCKS_DONE="$(sed -E 's/.*blocks=([0-9]+).*/\1/'      <<<"$RESULT_LINE")"
TXS_DONE="$(   sed -E 's/.*txs=([0-9]+).*/\1/'         <<<"$RESULT_LINE")"
BPS="$(        sed -E 's/.*blocks_per_sec=([0-9.]+).*/\1/' <<<"$RESULT_LINE")"
TPS="$(        sed -E 's/.*txs_per_sec=([0-9.]+).*/\1/'    <<<"$RESULT_LINE")"

# Peak RSS (avg CPU is meaningless for a sub-second single-threaded loop, so the
# decode schema omits it).
SUMMARY="$(bench_sampler_summary "$SAMPLE_CSV")"
PEAK_RSS_MB="$(awk '{print $1}' <<<"$SUMMARY")"
PEAK_RSS_MB="${PEAK_RSS_MB:-0}"

NOTES="decode-only: prost Block::decode + per-tx decode_tx_summary (protobuf \
param unpack + 4-byte selector -> method name + USDT ABI amount); corpus \
pre-loaded in memory, I/O excluded from the timed loop; single-threaded; native \
release build; same bytes + same scope as java"

# ---- emit decode-dimension JSON ---------------------------------------------
#
# This dimension's schema differs from the apply benchmark (no wall_clock_s /
# block range), so we write it directly rather than via bench_emit_json.
OUT_JSON="$OUT/decode-ours.json"
awk -v engine="ours" -v version="$GIT_SHA" \
    -v blocks="$BLOCKS_DONE" -v txs="$TXS_DONE" \
    -v bps="$BPS" -v tps="$TPS" -v rss="$PEAK_RSS_MB" \
    -v notes="$NOTES" '
  BEGIN {
    gsub(/\n/, " ", notes); gsub(/  +/, " ", notes)
    printf "{\n"
    printf "  \"dimension\": \"decode\",\n"
    printf "  \"engine\": \"%s\",\n", engine
    printf "  \"version\": \"%s\",\n", version
    printf "  \"blocks\": %d,\n", blocks + 0
    printf "  \"txs\": %d,\n", txs + 0
    printf "  \"blocks_per_sec\": %.1f,\n", bps + 0
    printf "  \"txs_per_sec\": %.1f,\n", tps + 0
    printf "  \"peak_rss_mb\": %.1f,\n", rss + 0
    printf "  \"notes\": \"%s\"\n", notes
    printf "}\n"
  }' > "$OUT_JSON"

echo "[decode-ours] wrote $OUT_JSON"
exit 0
