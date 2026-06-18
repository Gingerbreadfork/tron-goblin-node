#!/usr/bin/env bash
#
# java.sh -- the java-tron side of the "tron-goblin-node vs java-tron" benchmark.
#
# Runs a VANILLA (un-instrumented) java-tron FullNode and has it PEER-SYNC a
# fixed block range the SAME way ours.sh does, starting from the SAME snapshot
# pre-state (a private, writable COPY of the user-supplied read-only snapshot),
# on the SAME machine -- a real, symmetric sync race. It emits a single metric
# JSON (engine=java) into the results dir for report.py to pick up alongside the
# "ours" run.
#
# Why a real peer-sync (not a replay harness): a public benchmark lives or dies
# on credibility. Both engines must do the SAME work the SAME way -- sync the
# same range from the same source, from the same snapshot pre-state, on the same
# box. That is exactly what the TRON community cares about (java sync speed), and
# it removes any "your custom harness is doing less work" objection: this is
# stock java-tron's own sync path (PeerConnection -> Manager.pushBlock), no
# special replay program, no instrumentation.
#
# Fairness model:
#   * SAME block source: a pinned SYNC_PEER feeds both engines, or (when
#     SYNC_PEER is empty) both use public discovery + seeds.
#   * SAME snapshot pre-state -> both start from the snapshot head + 1.
#   * SAME machine, run in series (run.sh never runs them concurrently).
#   * The network path is identical for both, so it cancels out of the
#     comparison; the timed window is the sync of [FROM, TO] only.
#
# ISOLATION: this only ever READS the snapshot at SNAPSHOT_PATH and COPIES it
# into a BENCH_WORK data-dir it owns (a plain cp/rsync -- never a hard-link or
# reset of a shared directory). It never writes the snapshot and touches nothing
# outside BENCH_WORK. The FullNode jar is the vanilla jar bootstrap.sh builds.
# All inputs come from bench/bench.config.
#
# It samples the JVM's peak RSS and average CPU while the sync runs, and times
# the wall clock around the sync itself (the snapshot copy is timed separately
# as snapshot_load_s, so it does not pollute the throughput number).
#
# USAGE
#   bench/java.sh [--from N] [--to N] [--out DIR]
set -uo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
export BENCH_DIR
REPO_ROOT="$(cd "${BENCH_DIR}/.." && pwd)"
export REPO_ROOT
# shellcheck source=bench/lib.sh
source "${BENCH_DIR}/lib.sh"
# shellcheck source=bench/bench.config
source "${BENCH_DIR}/bench.config"

OUT="${RESULTS_DIR}"

usage() {
  cat <<EOF
usage: bench/java.sh [--from N] [--to N] [--out DIR]

  --from N   first block of the range (default ${FROM})
  --to N     last block to sync, inclusive (default ${TO})
  --out DIR  results dir for the emitted JSON (default ${OUT})

Runs the vanilla java-tron FullNode peer-syncing [--from, --to] from a copy of
SNAPSHOT_PATH and emits engine=java metric JSON. All paths come from
bench/bench.config (JAVA_TRON_JAR / JT_BUILT_JAR, JDK8_HOME, SNAPSHOT_PATH,
BENCH_WORK, SYNC_PEER, XMX, ...).
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from) FROM="$2"; shift 2;;
    --to)   TO="$2"; shift 2;;
    --out)  OUT="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "java.sh: unknown arg: $1" >&2; usage >&2; exit 1;;
  esac
done

if [[ "$FROM" -gt "$TO" ]]; then
  echo "java.sh: --from ($FROM) must be <= --to ($TO)" >&2
  exit 2
fi

# Vanilla FullNode jar: prefer an explicitly supplied JAVA_TRON_JAR, else the
# one bootstrap.sh built into BENCH_WORK.
JAR="${JAVA_TRON_JAR:-$JT_BUILT_JAR}"

# JDK 8 runtime (JDK8_HOME, else java on PATH).
JAVA_BIN="$(bench_java_bin "${JDK8_HOME}")" || {
  echo "java.sh: no java runtime found. Install JDK 8 and set JDK8_HOME/JAVA_HOME." >&2
  exit 1
}

# Dedicated bench DB (a writable COPY of the snapshot), under BENCH_WORK.
BENCH_JAVA_DATA="${SYNC_JAVA_DATA}"

# java-tron writes its application log to ./logs/tron.log relative to its CWD.
# We run the JVM with CWD = the bench DB dir, so the log lands there.
JT_LOG="${JT_LOG:-$BENCH_JAVA_DATA/logs/tron.log}"

# Per-run artifacts.
RUN_LOG="${RUN_LOG:-$OUT/java-${FROM}-${TO}.log}"
SAMPLE_CSV="${SAMPLE_CSV:-$OUT/java-${FROM}-${TO}.sample}"

# ---- guards -----------------------------------------------------------------

if [[ ! -d "$SNAPSHOT_PATH/database" ]]; then
  echo "java.sh: snapshot missing at $SNAPSHOT_PATH/database" >&2
  echo "         set SNAPSHOT_PATH or run bench/bootstrap.sh --only snapshot." >&2
  exit 1
fi
if [[ ! -f "$JAR" ]]; then
  echo "java.sh: java-tron jar not found: $JAR" >&2
  echo "         build it: bench/bootstrap.sh --only java  (or set JAVA_TRON_JAR)." >&2
  exit 1
fi
if ! bench_java_is_8 "${JAVA_BIN}"; then
  echo "java.sh: WARNING — ${JAVA_BIN} is not JDK 8; java-tron expects JDK 8." >&2
fi

# Bracket trick so pgrep never matches THIS script. Refuse if a java FullNode is
# already syncing our bench DB.
if pgrep -af '[o]rg.tron.program.FullNode' 2>/dev/null | grep -qF -- "$BENCH_JAVA_DATA"; then
  echo "java.sh: a java FullNode is already running against $BENCH_JAVA_DATA." >&2
  echo "         stop it before re-running this benchmark." >&2
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
    echo "         point BENCH_WORK at a bigger disk." >&2
    exit 1
  fi
fi

mkdir -p "$OUT"
: > "$RUN_LOG"
: > "$SAMPLE_CSV"
export BENCH_OUT_DIR="$OUT"

BLOCKS=$(( TO - FROM + 1 ))
echo "[bench-java] range [$FROM, $TO]  ($BLOCKS blocks)"
echo "[bench-java] bench DB: $BENCH_JAVA_DATA   (snapshot: $SNAPSHOT_PATH)"
echo "[bench-java] jar: $JAR   java: $JAVA_BIN   xmx: $XMX"

# ---- cleanup ----------------------------------------------------------------

JVM_PID=""
SAMPLER_PID=""
WATCHDOG_PID=""
cleanup() {
  [[ -n "$WATCHDOG_PID" ]] && kill "$WATCHDOG_PID" 2>/dev/null
  bench_stop_sampler "${SAMPLER_PID:-}"
  if [[ -n "$JVM_PID" ]] && kill -0 "$JVM_PID" 2>/dev/null; then
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

# ---- (a) copy-seed the dedicated bench DB from the snapshot (timed) ----------
#
# A PLAIN recursive copy of the read-only snapshot into our writable bench DB --
# never a hard-link or reset of a shared directory. The snapshot is never
# modified.
echo "[bench-java] copying bench DB from snapshot ..."
load_t0="$(bench_now_s)"
if ! bench_copy_snapshot "$SNAPSHOT_PATH" "$BENCH_JAVA_DATA"; then
  echo "java.sh: bench DB copy failed" >&2
  exit 1
fi
load_t1="$(bench_now_s)"
snapshot_load_s="$(bench_elapsed_s "$load_t0" "$load_t1")"
echo "[bench-java] snapshot_load_s=$snapshot_load_s"

# ---- vanilla mainnet config (peer-sync, all serving subsystems off) ----------
#
# A stock mainnet config: full genesis block + committee defaults so the node
# validates against the real chain, and every serving subsystem (HTTP/gRPC/
# jsonrpc/metrics/event-subscribe) OFF so nothing competes for CPU during
# measurement. Block source: when SYNC_PEER is set it is pinned as the sole
# upstream with discovery off (same single peer ours.sh uses); when SYNC_PEER is
# empty, discovery is on with the public JAVA_SEED_NODES. No instrumentation env
# is set -- this is a clean sync.
CONF="$BENCH_JAVA_DATA/bench-java.conf"

# Build the active-node + seed-node lists for the config.
if [[ -n "$SYNC_PEER" ]]; then
  peer_host="${SYNC_PEER%%:*}"
  peer_port="${SYNC_PEER##*:}"
  [[ -n "$peer_host" && -n "$peer_port" ]] \
    || { echo "java.sh: SYNC_PEER must be host:port (got '$SYNC_PEER')" >&2; exit 1; }
  DISCOVERY_ENABLE="false"
  ACTIVE_LINES="    \"$SYNC_PEER\""
  SEED_LINES="    \"$SYNC_PEER\""
  PEER_DESC="$SYNC_PEER (pinned, discovery off)"
else
  DISCOVERY_ENABLE="true"
  ACTIVE_LINES=""
  SEED_LINES="$(for s in $JAVA_SEED_NODES; do printf '    "%s"\n' "$s"; done)"
  PEER_DESC="public discovery + seed nodes"
fi

cat > "$CONF" <<EOF
# Generated by bench/java.sh -- vanilla java-tron mainnet config for a peer-sync
# of a fixed block range. Overwritten on every run; do not edit by hand.

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
  enable = ${DISCOVERY_ENABLE}
  persist = false
}

node {
  p2p {
    version = 11111 # mainnet
  }

  active = [
${ACTIVE_LINES}
  ]
  passive = []
  fastForward = []

  # Every serving subsystem OFF so the measured window is pure sync + apply.
  http {
    fullNodeEnable = false
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
  fetchBlock.timeout = 200
  maxConnections = 30
  minConnections = 1
  minActiveConnections = 1
  maxConnectionsWithSameIp = 2
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
  ip.list = [
${SEED_LINES}
  ]
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
  supportConstant = false
  maxEnergyLimitForConstant = 100000000
  minTimeRatio = 0.0
  maxTimeRatio = 5.0
  saveInternalTx = false
}

committee = {
  allowCreationOfContracts = 0
  allowAdaptiveEnergy = 0
}

# No event.subscribe block: a sync-only benchmark node has no use for triggers.
EOF

# ---- (b) launch the clean vanilla FullNode to PEER-SYNC [FROM, TO] -----------
#
# No -w (not a witness/producer): a pure sync node. CWD = bench DB dir so the
# app log lands at $JT_LOG. No instrumentation env is set. The sync clock starts
# here.
jdk_home="${JDK8_HOME:-$(dirname "$(dirname "${JAVA_BIN}")")}"
export JAVA_HOME="$jdk_home"

echo "[bench-java] starting vanilla FullNode peer-sync via ${PEER_DESC} -> $JT_LOG"
mkdir -p "$BENCH_JAVA_DATA/logs"
: > "$JT_LOG"

apply_t0="$(bench_now_s)"
(
  cd "$BENCH_JAVA_DATA" \
  && exec "$JAVA_BIN" \
       -Xms"$XMX" -Xmx"$XMX" -XX:+UseG1GC -XX:+AlwaysPreTouch \
       -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=500 \
       -jar "$JAR" -c "$CONF" -d "$BENCH_JAVA_DATA"
) >> "$RUN_LOG" 2>&1 &
JVM_PID=$!

# ---- (c) sample peak RSS + avg CPU of the JVM pid while it syncs --------------
SAMPLER_PID="$(bench_sample_proc "$JVM_PID" "$SAMPLE_CSV")" || SAMPLER_PID=""

# ---- (d) detect completion: synced head reaches TO ---------------------------
#
# During sync, java-tron logs one line per applied block to ./logs/tron.log:
#   "PushBlock block number: <N>, cost/txs: <ms>/<n> <bool>."
# We watch for N >= TO, then stop the JVM cleanly. A watchdog also aborts if the
# JVM dies on its own (crash / peer drop) so we never wait forever.
(
  reached=0
  while kill -0 "$JVM_PID" 2>/dev/null; do
    n="$(grep -oE 'PushBlock block number: [0-9]+' "$JT_LOG" 2>/dev/null \
         | grep -oE '[0-9]+$' | tail -1)"
    if [[ -n "$n" && "$n" -ge "$TO" ]]; then
      reached=1
      sleep 2
      kill -0 "$JVM_PID" 2>/dev/null && kill -TERM "$JVM_PID" 2>/dev/null
      break
    fi
    sleep 2
  done
  exit "$((reached == 1 ? 0 : 1))"
) &
WATCHDOG_PID=$!

# Block until the JVM exits (watchdog stopped it after reaching TO, or it died).
wait "$JVM_PID" 2>/dev/null
rc=$?
apply_t1="$(bench_now_s)"
JVM_PID=""   # reaped; stop cleanup() from re-killing.

# Reap the watchdog; its exit status tells us whether TO was actually reached.
TO_REACHED=no
if [[ -n "$WATCHDOG_PID" ]]; then
  if wait "$WATCHDOG_PID" 2>/dev/null; then
    TO_REACHED=yes
  fi
  WATCHDOG_PID=""
fi

bench_stop_sampler "$SAMPLER_PID"
SAMPLER_PID=""

# ---- (e) reduce samples + measured wall clock --------------------------------

wall_clock_s="$(bench_elapsed_s "$apply_t0" "$apply_t1")"
summary="$(bench_sampler_summary "$SAMPLE_CSV")"
peak_rss_mb="$(awk '{print $1}' <<<"$summary")"
avg_cpu_pct="$(awk '{print $2}' <<<"$summary")"
peak_rss_mb="${peak_rss_mb:-0}"
avg_cpu_pct="${avg_cpu_pct:-0}"

synced_head="$(grep -oE 'PushBlock block number: [0-9]+' "$JT_LOG" 2>/dev/null \
               | grep -oE '[0-9]+$' | tail -1)"
synced_head="${synced_head:-unknown}"

echo "[bench-java] sync exited rc=$rc  wall_clock_s=$wall_clock_s  to_reached=$TO_REACHED  head=$synced_head"
echo "[bench-java] peak_rss_mb=$peak_rss_mb  avg_cpu_pct=$avg_cpu_pct"

if [[ "$TO_REACHED" != "yes" ]]; then
  echo "java.sh: synced head did not reach $TO (last seen: $synced_head)." >&2
  echo "         the JVM exited before completing the range; see $RUN_LOG / $JT_LOG" >&2
  tail -20 "$RUN_LOG" "$JT_LOG" 2>/dev/null >&2
  exit 1
fi

# ---- (f) emit the metric JSON ------------------------------------------------

# version: the vanilla java-tron build under test (tag + short sha when the
# source repo bootstrap.sh cloned is present). Overridable via VERSION.
version="${VERSION:-}"
if [[ -z "$version" ]] && [[ -d "$JT_SRC_DIR/.git" ]]; then
  version="$(cd "$JT_SRC_DIR" \
    && printf '%s@%s' "$(git describe --tags 2>/dev/null || echo java-tron)" \
                      "$(git rev-parse --short HEAD 2>/dev/null || echo unknown)")"
fi
version="${version:-${JAVA_TRON_TAG}}"

notes="vanilla java-tron FullNode peer-sync via ${PEER_DESC}; -Xmx=$XMX heap \
inflates RSS; same source/snapshot/range as ours; clean (un-instrumented) jar; \
synced_head=$synced_head rc=$rc; snapshot copy timed separately as snapshot_load_s"

bench_emit_json java "$version" "$FROM" "$TO" \
  "$snapshot_load_s" "$wall_clock_s" "$peak_rss_mb" "$avg_cpu_pct" "$notes"

echo "[bench-java] wrote metric JSON to $OUT"
exit 0
