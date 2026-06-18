#!/usr/bin/env bash
#
# bench/rpc/java.sh -- vanilla java-tron ("java") runner for the QUERY/RPC
# performance + steady-state RAM dimension of the "vs java-tron" benchmark.
#
# Runs a VANILLA (un-instrumented) java-tron FullNode as a pure QUERY SERVER
# over a COPY of the user-supplied snapshot, read-only, with sync OFF (no peers)
# so it just serves the static state -- the byte-identical counterpart to
# bench/rpc/ours.sh. It:
#
#   1. seeds a DEDICATED bench DB by COPYING the snapshot (timed as
#      snapshot_load_s) -- a plain copy of the read-only source into a data-dir
#      the suite owns under BENCH_WORK; the snapshot is never written;
#   2. starts the FullNode with the HTTP /wallet/* API on; gRPC + jsonrpc +
#      metrics + discovery OFF, no active/seed peers (static snapshot), and
#      vm.supportConstant = true so the read-only triggerConstantContract query
#      works;
#   3. waits until it answers a health query (getnowblock);
#   4. measures STEADY-STATE IDLE RSS -- samples RSS for ~5 s with NO load (the
#      RAM dimension; note the JVM heap inflates this, called out in notes);
#   5. runs the SHARED query plan (queries.json) through the SHARED load
#      generator (loadgen.py) while sampling peak RSS + CPU;
#   6. stops the node cleanly and emits results/rpc-java.json.
#
# Fairness model (see bench/rpc/README.md): both engines serve the SAME snapshot
# read-only, on the SAME machine, hit by the SAME query plan over the SAME HTTP
# /wallet/* protocol, run in ISOLATION.
#
# ISOLATION: this only READS the snapshot at SNAPSHOT_PATH and COPIES it into a
# BENCH_WORK data-dir it owns (a plain cp/rsync -- never a hard-link or reset of
# a shared directory). The jar is the vanilla jar bootstrap.sh builds. All
# inputs come from bench/bench.config.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH_DIR="$(cd "${HERE}/.." && pwd)"
export BENCH_DIR
REPO_ROOT="$(cd "${BENCH_DIR}/.." && pwd)"
export REPO_ROOT
# shellcheck source=bench/lib.sh
source "${BENCH_DIR}/lib.sh"
# shellcheck source=bench/bench.config
source "${BENCH_DIR}/bench.config"

# ---------------------------------------------------------------------------
# Inputs / locations (from bench.config; overridable by environment).
# ---------------------------------------------------------------------------

OUT="${RESULTS_DIR}"

# Vanilla FullNode jar (prefer an explicit JAVA_TRON_JAR, else bootstrap's).
JAR="${JAVA_TRON_JAR:-$JT_BUILT_JAR}"

# JDK 8 runtime (JDK8_HOME, else java on PATH).
JAVA_BIN="$(bench_java_bin "${JDK8_HOME}")" || {
    echo "java.sh: no java runtime found. Install JDK 8 and set JDK8_HOME/JAVA_HOME." >&2
    exit 1
}

# Dedicated bench DB (a writable COPY of the snapshot), under BENCH_WORK.
BENCH_JAVA_DATA="${RPC_JAVA_DATA}"

# HTTP /wallet/* API the load generator hits.
BASE_URL="http://${HTTP_HOST}:${HTTP_PORT}"

# Shared query plan + load generator + JSON emitter.
PLAN="${PLAN:-${HERE}/queries.json}"
LOADGEN="${HERE}/loadgen.py"
EMIT="${HERE}/emit_rpc_json.py"

HEALTH_TIMEOUT_S="${HEALTH_TIMEOUT_JAVA_S}"

# java-tron application log (its CWD = the bench DB dir).
JT_LOG="${JT_LOG:-$BENCH_JAVA_DATA/logs/tron.log}"

usage() {
    cat <<EOF
usage: bench/rpc/java.sh [--out DIR]

  --out DIR   results directory (default ${OUT})

Stands a vanilla java-tron FullNode up as a read-only query server over a copy
of SNAPSHOT_PATH, measures steady-state idle RSS, runs the shared query plan
through the shared load generator, and emits results/rpc-java.json. All paths
come from bench/bench.config (JAVA_TRON_JAR / JT_BUILT_JAR, JDK8_HOME,
SNAPSHOT_PATH, BENCH_WORK, HTTP_HOST, HTTP_PORT, XMX, ...).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs DIR}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "java.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Guards.
# ---------------------------------------------------------------------------
if [ ! -d "$SNAPSHOT_PATH/database" ]; then
    echo "java.sh: snapshot missing at $SNAPSHOT_PATH/database" >&2
    echo "         set SNAPSHOT_PATH or run bench/bootstrap.sh --only snapshot." >&2
    exit 1
fi
if [ ! -f "$JAR" ]; then
    echo "java.sh: java-tron jar not found: $JAR" >&2
    echo "         build it: bench/bootstrap.sh --only java (or set JAVA_TRON_JAR)." >&2
    exit 1
fi
for f in "${PLAN}" "${LOADGEN}" "${EMIT}"; do
    [ -e "$f" ] || { echo "java.sh: required file missing: $f" >&2; exit 1; }
done
if ! command -v python3 >/dev/null 2>&1; then
    echo "java.sh: python3 is required (load generator + JSON emitter)." >&2
    exit 1
fi
if ! bench_java_is_8 "${JAVA_BIN}"; then
    echo "java.sh: WARNING — ${JAVA_BIN} is not JDK 8; java-tron expects JDK 8." >&2
fi

# Bracket trick so pgrep never matches THIS script. Refuse if a java FullNode is
# already serving our bench DB.
if pgrep -af '[o]rg.tron.program.FullNode' 2>/dev/null | grep -qF -- "$BENCH_JAVA_DATA"; then
    echo "java.sh: a java FullNode is already running against $BENCH_JAVA_DATA." >&2
    exit 1
fi
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE "[: ]${HTTP_PORT}\b"; then
    echo "java.sh: port ${HTTP_PORT} is already in use; set HTTP_PORT to a free port." >&2
    exit 1
fi

# Disk-space preflight: the copy duplicates the snapshot.
mkdir -p "${BENCH_WORK}"
snap_mib=$(du -sm "${SNAPSHOT_PATH}/database" 2>/dev/null | cut -f1)
free_mib=$(df -Pm "${BENCH_WORK}" 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${snap_mib:-}" ] && [ -n "${free_mib:-}" ]; then
    need_mib=$(( snap_mib + 2048 ))
    if [ "${free_mib}" -lt "${need_mib}" ]; then
        echo "java.sh: not enough free space under BENCH_WORK for a snapshot copy." >&2
        echo "         snapshot ~${snap_mib} MiB, free ${free_mib} MiB, need ~${need_mib} MiB." >&2
        exit 1
    fi
fi

mkdir -p "$OUT"
RUN_LOG="${OUT}/rpc-java.log"
SAMPLE_IDLE="${OUT}/rpc-java.idle.sample"
SAMPLE_LOAD="${OUT}/rpc-java.load.sample"
LOADGEN_OUT="${OUT}/rpc-java.queries.json"
: > "$RUN_LOG"

echo "[bench-rpc-java] bench DB: $BENCH_JAVA_DATA   (snapshot: $SNAPSHOT_PATH)"
echo "[bench-rpc-java] jar: $JAR   java: $JAVA_BIN   xmx: $XMX   http: $BASE_URL"

# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------
JVM_PID=""
SAMPLER_PID=""
cleanup() {
    bench_stop_sampler "${SAMPLER_PID:-}"
    if [ -n "$JVM_PID" ] && kill -0 "$JVM_PID" 2>/dev/null; then
        kill -TERM "$JVM_PID" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "$JVM_PID" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "$JVM_PID" 2>/dev/null
        wait "$JVM_PID" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# (a) Seed the dedicated bench DB by COPYING the snapshot (timed).
#
#     A plain recursive copy of the read-only snapshot into our writable bench
#     DB -- never a hard-link or reset of a shared directory. The snapshot is
#     never modified.
# ---------------------------------------------------------------------------
echo "[bench-rpc-java] copying bench DB from snapshot ..."
load_t0="$(bench_now_s)"
if ! bench_copy_snapshot "$SNAPSHOT_PATH" "$BENCH_JAVA_DATA"; then
    echo "java.sh: bench DB copy failed" >&2
    exit 1
fi
load_t1="$(bench_now_s)"
SNAPSHOT_LOAD_S="$(bench_elapsed_s "$load_t0" "$load_t1")"
echo "[bench-rpc-java] snapshot_load_s=$SNAPSHOT_LOAD_S"

# ---------------------------------------------------------------------------
# Vanilla mainnet config: a pure QUERY SERVER. The HTTP /wallet/* full-node API
# is ON (port HTTP_PORT); discovery + every other serving subsystem (gRPC /
# jsonrpc / metrics / event-subscribe) OFF; no active/seed/passive peers (the
# node serves the static snapshot and never syncs). vm.supportConstant = true so
# the read-only triggerConstantContract query exercises the VM read path.
# ---------------------------------------------------------------------------
CONF="$BENCH_JAVA_DATA/bench-rpc-java.conf"
cat > "$CONF" <<EOF
# Generated by bench/rpc/java.sh -- vanilla java-tron mainnet config for a
# read-only query server (HTTP /wallet/* on, no sync, no peers). Overwritten on
# every run; do not edit by hand.

net {
  type = mainnet
}

storage {
  db.engine = "ROCKSDB"
  db.sync = false
  db.directory = "database"
  transHistory.switch = "on"
  needToUpdateAsset = true
  dbSettings = {
    levelNumber = 7
    compactThreads = 32
    blocksize = 64
    maxBytesForLevelBase = 256
    maxBytesForLevelMultiplier = 10
    level0FileNumCompactionTrigger = 4
    targetFileSizeBase = 256
    targetFileSizeMultiplier = 1
    maxOpenFiles = 5000
  }
  txCache.initOptimization = true
}

node.discovery = {
  enable = false
  persist = false
}

node {
  p2p {
    version = 11111 # mainnet
  }

  # Pure query server: no upstream peers, never syncs.
  active = []
  passive = []
  fastForward = []

  # HTTP /wallet/* full-node API ON; everything else OFF.
  http {
    fullNodeEnable = true
    fullNodePort = ${HTTP_PORT}
    solidityEnable = false
    PBFTEnable = false
  }
  rpc {
    enable = false
    solidityEnable = false
    PBFTEnable = false
  }
  jsonrpc {
    httpFullNodeEnable = false
    httpSolidityEnable = false
    httpPBFTEnable = false
  }

  listen.port = 18899
  connection.timeout = 2
  maxConnections = 0
  minConnections = 0
  minActiveConnections = 0
  maxConnectionsWithSameIp = 0
  isOpenFullTcpDisconnect = false
  inactiveThreshold = 600
}

node.metrics = {
  prometheus {
    enable = false
  }
  storageEnable = false
}

seed.node = {
  ip.list = []
}

genesis.block = {
  assets = [
    { accountName = "Zion",      accountType = "AssetIssue", address = "TLLM21wteSPs4hKjbxgmH1L6poyMjeTbHm", balance = "99000000000000000" },
    { accountName = "Sun",       accountType = "AssetIssue", address = "TXmVpin5vq5gdZsciyyjdZgKRUju4st1wM", balance = "0" },
    { accountName = "Blackhole", accountType = "AssetIssue", address = "TLsV52sRDL79HXGGm9yzwKibb6BeruhUzy", balance = "-9223372036854775808" }
  ]
  witnesses = [
    { address: THKJYuUmMKKARNf7s2VT51g5uPY6KEqnat, url = "http://GR1.com",  voteCount = 100000026 },
    { address: TVDmPWGYxgi5DNeW8hXrzrhY8Y6zgxPNg4, url = "http://GR2.com",  voteCount = 100000025 },
    { address: TWKZN1JJPFydd5rMgMCV5aZTSiwmoksSZv, url = "http://GR3.com",  voteCount = 100000024 },
    { address: TDarXEG2rAD57oa7JTK785Yb2Et32UzY32, url = "http://GR4.com",  voteCount = 100000023 },
    { address: TAmFfS4Tmm8yKeoqZN8x51ASwdQBdnVizt, url = "http://GR5.com",  voteCount = 100000022 },
    { address: TK6V5Pw2UWQWpySnZyCDZaAvu1y48oRgXN, url = "http://GR6.com",  voteCount = 100000021 },
    { address: TGqFJPFiEqdZx52ZR4QcKHz4Zr3QXA24VL, url = "http://GR7.com",  voteCount = 100000020 },
    { address: TC1ZCj9Ne3j5v3TLx5ZCDLD55MU9g3XqQW, url = "http://GR8.com",  voteCount = 100000019 },
    { address: TWm3id3mrQ42guf7c4oVpYExyTYnEGy3JL, url = "http://GR9.com",  voteCount = 100000018 },
    { address: TCvwc3FV3ssq2rD82rMmjhT4PVXYTsFcKV, url = "http://GR10.com", voteCount = 100000017 },
    { address: TFuC2Qge4GxA2U9abKxk1pw3YZvGM5XRir, url = "http://GR11.com", voteCount = 100000016 },
    { address: TNGoca1VHC6Y5Jd2B1VFpFEhizVk92Rz85, url = "http://GR12.com", voteCount = 100000015 },
    { address: TLCjmH6SqGK8twZ9XrBDWpBbfyvEXihhNS, url = "http://GR13.com", voteCount = 100000014 },
    { address: TEEzguTtCihbRPfjf1CvW8Euxz1kKuvtR9, url = "http://GR14.com", voteCount = 100000013 },
    { address: TZHvwiw9cehbMxrtTbmAexm9oPo4eFFvLS, url = "http://GR15.com", voteCount = 100000012 },
    { address: TGK6iAKgBmHeQyp5hn3imB71EDnFPkXiPR, url = "http://GR16.com", voteCount = 100000011 },
    { address: TLaqfGrxZ3dykAFps7M2B4gETTX1yixPgN, url = "http://GR17.com", voteCount = 100000010 },
    { address: TX3ZceVew6yLC5hWTXnjrUFtiFfUDGKGty, url = "http://GR18.com", voteCount = 100000009 },
    { address: TYednHaV9zXpnPchSywVpnseQxY9Pxw4do, url = "http://GR19.com", voteCount = 100000008 },
    { address: TCf5cqLffPccEY7hcsabiFnMfdipfyryvr, url = "http://GR20.com", voteCount = 100000007 },
    { address: TAa14iLEKPAetX49mzaxZmH6saRxcX7dT5, url = "http://GR21.com", voteCount = 100000006 },
    { address: TBYsHxDmFaRmfCF3jZNmgeJE8sDnTNKHbz, url = "http://GR22.com", voteCount = 100000005 },
    { address: TEVAq8dmSQyTYK7uP1ZnZpa6MBVR83GsV6, url = "http://GR23.com", voteCount = 100000004 },
    { address: TRKJzrZxN34YyB8aBqqPDt7g4fv6sieemz, url = "http://GR24.com", voteCount = 100000003 },
    { address: TRMP6SKeFUt5NtMLzJv8kdpYuHRnEGjGfe, url = "http://GR25.com", voteCount = 100000002 },
    { address: TDbNE1VajxjpgM5p7FyGNDASt3UVoFbiD3, url = "http://GR26.com", voteCount = 100000001 },
    { address: TLTDZBcPoJ8tZ6TTEeEqEvwYFk2wgotSfD, url = "http://GR27.com", voteCount = 100000000 }
  ]
  timestamp = "0"
  parentHash = "0xe58f33f9baf9305dc6f82b9f1934ea8f0ade2defb951258d50167028c780351f"
}

localwitness = [
]

block = {
  needSyncCheck = true
  maintenanceTimeInterval = 21600000
  proposalExpireTime = 259200000
}

trx.reference.block = "solid"

vm = {
  # Read-only constant calls (triggerConstantContract) -- the VM read path this
  # dimension stresses. Matches ours.sh's vm.support_constant = true.
  supportConstant = true
  maxEnergyLimitForConstant = 100000000
  minTimeRatio = 0.0
  maxTimeRatio = 5.0
  saveInternalTx = false
}

committee = {
  allowCreationOfContracts = 0
  allowAdaptiveEnergy = 0
}
EOF

# ---------------------------------------------------------------------------
# (b) Launch the vanilla FullNode as a query server. No -w (not a producer).
#     CWD = bench DB dir so the app log lands at $JT_LOG. No instrumentation env.
# ---------------------------------------------------------------------------
jdk_home="${JDK8_HOME:-$(dirname "$(dirname "${JAVA_BIN}")")}"
export JAVA_HOME="$jdk_home"
echo "[bench-rpc-java] starting vanilla FullNode query server -> $JT_LOG"
mkdir -p "$BENCH_JAVA_DATA/logs"
: > "$JT_LOG"

(
  cd "$BENCH_JAVA_DATA" \
  && exec "$JAVA_BIN" \
       -Xms"$XMX" -Xmx"$XMX" -XX:+UseG1GC -XX:+AlwaysPreTouch \
       -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=500 \
       -jar "$JAR" -c "$CONF" -d "$BENCH_JAVA_DATA"
) >> "$RUN_LOG" 2>&1 &
JVM_PID=$!

# ---------------------------------------------------------------------------
# (c) Wait until the HTTP server answers the health query (getnowblock).
# ---------------------------------------------------------------------------
healthy=no
for _ in $(seq 1 "${HEALTH_TIMEOUT_S}"); do
    if ! kill -0 "$JVM_PID" 2>/dev/null; then
        echo "java.sh: JVM exited during startup; see $RUN_LOG / $JT_LOG" >&2
        tail -20 "$RUN_LOG" >&2
        exit 1
    fi
    body="$(curl -s -m 3 -X POST "${BASE_URL}/wallet/getnowblock" 2>/dev/null)"
    if printf '%s' "${body}" | grep -q 'blockID'; then
        healthy=yes
        break
    fi
    sleep 1
done
if [ "$healthy" != "yes" ]; then
    echo "java.sh: HTTP server did not answer getnowblock within ${HEALTH_TIMEOUT_S}s." >&2
    tail -20 "$RUN_LOG" >&2
    exit 1
fi
echo "[bench-rpc-java] server healthy."

# ---------------------------------------------------------------------------
# (d) Steady-state IDLE RSS -- sample for IDLE_SAMPLE_S with NO load.
# ---------------------------------------------------------------------------
echo "[bench-rpc-java] measuring steady-state idle RSS for ${IDLE_SAMPLE_S}s..."
: > "$SAMPLE_IDLE"
SAMPLER_PID="$(bench_sample_proc "$JVM_PID" "$SAMPLE_IDLE")" || SAMPLER_PID=""
sleep "${IDLE_SAMPLE_S}"
bench_stop_sampler "$SAMPLER_PID"
SAMPLER_PID=""
IDLE_SUMMARY="$(bench_sampler_summary "$SAMPLE_IDLE")"
IDLE_RSS_MB="$(awk '{print $1}' <<<"$IDLE_SUMMARY")"
IDLE_RSS_MB="${IDLE_RSS_MB:-0}"
echo "[bench-rpc-java] idle_rss_mb=$IDLE_RSS_MB"

# ---------------------------------------------------------------------------
# (e) Run the shared query plan through the shared load generator while
#     sampling peak RSS + CPU.
# ---------------------------------------------------------------------------
echo "[bench-rpc-java] running query load plan (sampling peak RSS + CPU)..."
: > "$SAMPLE_LOAD"
SAMPLER_PID="$(bench_sample_proc "$JVM_PID" "$SAMPLE_LOAD")" || SAMPLER_PID=""

python3 "$LOADGEN" \
    --base-url "$BASE_URL" \
    --plan "$PLAN" \
    --out "$LOADGEN_OUT" \
    >> "$RUN_LOG" 2>&1
LOADGEN_RC=$?

bench_stop_sampler "$SAMPLER_PID"
SAMPLER_PID=""

if [ "$LOADGEN_RC" -ne 0 ] || [ ! -s "$LOADGEN_OUT" ]; then
    echo "java.sh: load generator failed (rc=$LOADGEN_RC); see $RUN_LOG" >&2
    tail -20 "$RUN_LOG" >&2
    exit 1
fi

LOAD_SUMMARY="$(bench_sampler_summary "$SAMPLE_LOAD")"
PEAK_RSS_MB="$(awk '{print $1}' <<<"$LOAD_SUMMARY")"
AVG_CPU_PCT="$(awk '{print $2}' <<<"$LOAD_SUMMARY")"
PEAK_RSS_MB="${PEAK_RSS_MB:-0}"
AVG_CPU_PCT="${AVG_CPU_PCT:-0}"
echo "[bench-rpc-java] peak_rss_mb=$PEAK_RSS_MB avg_cpu_pct=$AVG_CPU_PCT"

# ---------------------------------------------------------------------------
# (f) Stop the JVM cleanly.
# ---------------------------------------------------------------------------
kill -TERM "$JVM_PID" 2>/dev/null
for _ in $(seq 1 30); do
    kill -0 "$JVM_PID" 2>/dev/null || break
    sleep 1
done
kill -KILL "$JVM_PID" 2>/dev/null
wait "$JVM_PID" 2>/dev/null
JVM_PID=""

# ---------------------------------------------------------------------------
# (g) Emit the RPC-dimension result JSON.
# ---------------------------------------------------------------------------
version="${VERSION:-}"
if [ -z "$version" ] && [ -d "$JT_SRC_DIR/.git" ]; then
    version="$(cd "$JT_SRC_DIR" \
        && printf '%s@%s' "$(git describe --tags 2>/dev/null || echo java-tron)" \
                          "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)")"
fi
version="${version:-${JAVA_TRON_TAG}}"

NOTES="vanilla java-tron FullNode read-only query server over a copy of the \
snapshot; HTTP /wallet/* full-node API; no peers / no sync; \
vm.supportConstant=true; -Xms=-Xmx=$XMX pre-touched heap INFLATES idle/peak RSS \
(reflects configured heap, not working set); clean (un-instrumented) jar; \
snapshot seeded by plain copy; same snapshot/plan/protocol as ours, run in \
isolation"

python3 "$EMIT" \
    --out "${OUT}/rpc-java.json" \
    --engine java \
    --version "$version" \
    --idle-rss-mb "$IDLE_RSS_MB" \
    --peak-rss-mb "$PEAK_RSS_MB" \
    --avg-cpu-pct "$AVG_CPU_PCT" \
    --queries-json "$LOADGEN_OUT" \
    --notes "$NOTES"

echo "[bench-rpc-java] done -- wrote ${OUT}/rpc-java.json"
exit 0
