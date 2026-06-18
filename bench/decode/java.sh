#!/usr/bin/env bash
#
# bench/decode/java.sh -- java-tron side of the DECODE-throughput microbenchmark.
#
# Compiles (if needed) and runs DecodeBench against the VANILLA java-tron
# classpath (the FullNode jar bootstrap.sh builds). DecodeBench loads the first
# --count blocks of the shared length-prefixed corpus into memory (untimed),
# runs JIT-warmup passes that are NOT counted, then times a measured pass that:
#   * Protocol.Block.parseFrom(bytes);
#   * iterates getTransactionsList();
#   * for the first contract of each tx, unpacks the typed parameter Any
#     (TransferContract / TransferAssetContract / TriggerSmartContract) and, for
#     a contract call, reads the 4-byte selector -> method name + USDT ABI amount.
# This is the SAME logical decode the Rust side does over the SAME bytes; see
# bench/decode/README.md for the exact scope contract.
#
# It samples peak RSS of the JVM via lib.sh's bench_sample_proc and emits
# bench/results/decode-java.json with the decode-dimension schema:
#
#   { "dimension":"decode", "engine":"java", "version", "blocks", "txs",
#     "blocks_per_sec", "txs_per_sec", "peak_rss_mb", "notes" }
#
# The vanilla jar + JDK + corpus all come from bench/bench.config.
#
# USAGE
#   bench/decode/java.sh [--count N] [--blocks FILE] [--out DIR]
#                        [--warmup N] [--measured N]
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
WARMUP=3      # JIT-warmup passes (excluded from timing)
MEASURED=3    # timed passes (averaged); blocks/txs reported are per single pass
OUT="$RESULTS_DIR"
BLOCKS="$BLOCKS_FILE"

# Vanilla FullNode jar (prefer an explicit JAVA_TRON_JAR, else bootstrap's).
JAR="${JAVA_TRON_JAR:-$JT_BUILT_JAR}"

# Decode-run heap. Modest by default -- the corpus + parsed objects are the
# working set, not a chain heap. -Xmx still inflates RSS vs the native process.
DECODE_XMX="${DECODE_XMX:-4g}"

usage() {
  cat <<EOF
usage: bench/decode/java.sh [--count N] [--blocks FILE] [--out DIR] [--warmup N] [--measured N]

  --count N      number of leading corpus blocks to decode (default ${COUNT})
  --blocks FILE  shared length-prefixed .blocks corpus      (default ${BLOCKS})
  --out DIR      results directory                          (default ${OUT})
  --warmup N     JIT-warmup passes (excluded from timing)   (default ${WARMUP})
  --measured N   timed passes, averaged                     (default ${MEASURED})

Decode-only microbenchmark for the java-tron engine. Emits decode-java.json.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --count)    COUNT="${2:?--count needs N}"; shift 2 ;;
    --blocks)   BLOCKS="${2:?--blocks needs FILE}"; shift 2 ;;
    --out)      OUT="${2:?--out needs DIR}"; shift 2 ;;
    --warmup)   WARMUP="${2:?--warmup needs N}"; shift 2 ;;
    --measured) MEASURED="${2:?--measured needs N}"; shift 2 ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "java.sh(decode): unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- guards -----------------------------------------------------------------

JAVA_BIN="$(bench_java_bin "${JDK8_HOME}")" || {
  echo "java.sh(decode): no java runtime found. Install JDK 8 + set JDK8_HOME/JAVA_HOME." >&2
  exit 1
}
JAVAC_BIN="$(bench_javac_bin "${JDK8_HOME}")" || {
  echo "java.sh(decode): no javac found (need a JDK, not just a JRE)." >&2
  exit 1
}
if [ ! -f "$JAR" ]; then
  echo "java.sh(decode): java-tron jar not found: $JAR" >&2
  echo "                 build it: bench/bootstrap.sh --only java (or set JAVA_TRON_JAR)." >&2
  exit 1
fi
if [ ! -f "$BLOCKS" ]; then
  echo "java.sh(decode): corpus not found: $BLOCKS" >&2
  echo "                 fetch it: bench/bootstrap.sh --only corpus, or set BLOCKS_FILE." >&2
  exit 1
fi
if ! [ "$COUNT" -gt 0 ] 2>/dev/null; then
  echo "java.sh(decode): --count must be a positive integer (got '$COUNT')." >&2
  exit 1
fi
if ! bench_java_is_8 "${JAVA_BIN}"; then
  echo "java.sh(decode): WARNING — ${JAVA_BIN} is not JDK 8; java-tron expects JDK 8." >&2
fi

mkdir -p "$OUT"
export BENCH_OUT_DIR="$OUT"
jdk_home="${JDK8_HOME:-$(dirname "$(dirname "${JAVA_BIN}")")}"
export JAVA_HOME="$jdk_home"

SRC="$HERE/java/DecodeBench.java"
CLASSES="$HERE/java/classes"
RUN_LOG="$OUT/decode-java-${COUNT}.log"
SAMPLE_CSV="$OUT/decode-java-${COUNT}.sample"
: > "$RUN_LOG"
: > "$SAMPLE_CSV"

# ---- build (only if the class is stale relative to the source) --------------

mkdir -p "$CLASSES"
if [ ! -f "$CLASSES/DecodeBench.class" ] || [ "$SRC" -nt "$CLASSES/DecodeBench.class" ]; then
  echo "[decode-java] compiling DecodeBench against $JAR ..."
  if ! "$JAVAC_BIN" -cp "$JAR" -d "$CLASSES" "$SRC" >>"$RUN_LOG" 2>&1; then
    echo "ERROR: javac failed; see $RUN_LOG" >&2
    tail -20 "$RUN_LOG" >&2
    exit 1
  fi
fi

echo "[decode-java] corpus : $BLOCKS"
echo "[decode-java] count  : $COUNT blocks  (warmup=$WARMUP measured=$MEASURED)"
echo "[decode-java] jar    : $JAR   java: $JAVA_BIN   xmx: $DECODE_XMX"

# ---- cleanup ----------------------------------------------------------------

JVM_PID=""
SAMPLER_PID=""
cleanup() {
  bench_stop_sampler "${SAMPLER_PID:-}"
  if [ -n "$JVM_PID" ] && kill -0 "$JVM_PID" 2>/dev/null; then
    kill -TERM "$JVM_PID" 2>/dev/null
    wait "$JVM_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

# ---- run + sample -----------------------------------------------------------

"$JAVA_BIN" -Xms"$DECODE_XMX" -Xmx"$DECODE_XMX" -XX:+UseG1GC \
  -cp "$CLASSES:$JAR" DecodeBench "$BLOCKS" "$COUNT" "$WARMUP" "$MEASURED" \
  >"$RUN_LOG" 2>&1 &
JVM_PID=$!

SAMPLER_PID="$(bench_sample_proc "$JVM_PID" "$SAMPLE_CSV")" || SAMPLER_PID=""

wait "$JVM_PID" 2>/dev/null
RC=$?
JVM_PID=""
bench_stop_sampler "$SAMPLER_PID"
SAMPLER_PID=""

if [ "$RC" -ne 0 ]; then
  echo "ERROR: DecodeBench exited rc=$RC; see $RUN_LOG" >&2
  tail -20 "$RUN_LOG" >&2
  exit 1
fi

RESULT_LINE="$(grep -E '^bench-decode: blocks=' "$RUN_LOG" | tail -1)"
if [ -z "$RESULT_LINE" ]; then
  echo "ERROR: did not find the bench-decode result line in $RUN_LOG" >&2
  tail -20 "$RUN_LOG" >&2
  exit 1
fi
echo "[decode-java] $RESULT_LINE"

BLOCKS_DONE="$(sed -E 's/.*blocks=([0-9]+).*/\1/'      <<<"$RESULT_LINE")"
TXS_DONE="$(   sed -E 's/.*txs=([0-9]+).*/\1/'         <<<"$RESULT_LINE")"
BPS="$(        sed -E 's/.*blocks_per_sec=([0-9.]+).*/\1/' <<<"$RESULT_LINE")"
TPS="$(        sed -E 's/.*txs_per_sec=([0-9.]+).*/\1/'    <<<"$RESULT_LINE")"

SUMMARY="$(bench_sampler_summary "$SAMPLE_CSV")"
PEAK_RSS_MB="$(awk '{print $1}' <<<"$SUMMARY")"
PEAK_RSS_MB="${PEAK_RSS_MB:-0}"

# version: the vanilla java-tron build under test.
VERSION="${VERSION:-}"
if [ -z "$VERSION" ] && [ -d "$JT_SRC_DIR/.git" ]; then
  VERSION="$(cd "$JT_SRC_DIR" && printf '%s@%s' \
    "$(git describe --tags 2>/dev/null || echo java-tron)" \
    "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)")"
fi
VERSION="${VERSION:-${JAVA_TRON_TAG}}"

NOTES="decode-only: Protocol.Block.parseFrom + per-tx Any.unpack (typed param) \
+ 4-byte selector -> method name + USDT ABI amount; vanilla java-tron classes, \
no instrumentation; corpus pre-loaded in memory, I/O excluded from the timed \
loop; ${WARMUP} JIT-warmup pass(es) excluded, ${MEASURED} measured pass(es) \
averaged; -Xmx=${DECODE_XMX} heap inflates RSS vs native; same bytes + same scope as ours"

OUT_JSON="$OUT/decode-java.json"
awk -v engine="java" -v version="$VERSION" \
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

echo "[decode-java] wrote $OUT_JSON"
exit 0
