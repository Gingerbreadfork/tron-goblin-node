#!/usr/bin/env bash
#
# bench/rpc/ours.sh -- tron-goblin-node ("ours") runner for the QUERY/RPC
# performance + steady-state RAM dimension of the "vs java-tron" benchmark.
#
# It stands our node up as a pure QUERY SERVER over a COPY of the user-supplied
# snapshot, read-only, with sync/p2p OFF so it just serves the static state,
# then:
#
#   1. seeds a DEDICATED bench data-dir by COPYING the snapshot (timed as
#      snapshot_load_s) -- a plain copy of the read-only source into a data-dir
#      the suite owns under BENCH_WORK; the snapshot is never written;
#   2. starts the node with the HTTP /wallet/* API on, gRPC + metrics off, sync
#      off, and vm.support_constant = true so the read-only
#      triggerConstantContract query works;
#   3. waits until it answers a health query (getnowblock);
#   4. measures STEADY-STATE IDLE RSS -- samples RSS for ~5 s with NO load (the
#      RAM dimension);
#   5. runs the SHARED query plan (queries.json) through the SHARED load
#      generator (loadgen.py) while sampling peak RSS + CPU;
#   6. stops the node cleanly and emits results/rpc-ours.json.
#
# Fairness model (see bench/rpc/README.md): both engines serve the SAME snapshot
# read-only, on the SAME machine, hit by the SAME query plan over the SAME HTTP
# /wallet/* protocol, run in ISOLATION. The counterpart runner is
# bench/rpc/java.sh.
#
# ISOLATION: this only READS the snapshot at SNAPSHOT_PATH and COPIES it into a
# BENCH_WORK data-dir it owns. It never hard-links/resets/writes any shared
# directory. All inputs come from bench/bench.config.

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

# Dedicated bench data-dir (a writable COPY of the snapshot), under BENCH_WORK.
DATA_DIR="${RPC_OURS_DATA}"

# HTTP /wallet/* API the load generator hits.
BASE_URL="http://${HTTP_HOST}:${HTTP_PORT}"

# Shared query plan + load generator + JSON emitter.
PLAN="${PLAN:-${HERE}/queries.json}"
LOADGEN="${HERE}/loadgen.py"
EMIT="${HERE}/emit_rpc_json.py"

HEALTH_TIMEOUT_S="${HEALTH_TIMEOUT_OURS_S}"

usage() {
    cat <<EOF
usage: bench/rpc/ours.sh [--out DIR]

  --out DIR   results directory (default ${OUT})

Stands tron-goblin-node up as a read-only query server over a copy of
SNAPSHOT_PATH, measures steady-state idle RSS, runs the shared query plan
through the shared load generator, and emits results/rpc-ours.json. All paths
come from bench/bench.config (SNAPSHOT_PATH, BENCH_WORK, TRON_NODE, HTTP_HOST,
HTTP_PORT, ...).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT="${2:?--out needs DIR}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ours.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ---------------------------------------------------------------------------
# Guards: fail fast and clearly before touching anything.
# ---------------------------------------------------------------------------

if [ ! -x "${TRON_NODE}" ]; then
    echo "ours.sh: ${TRON_NODE} not found or not executable." >&2
    echo "         build it first: bench/bootstrap.sh --only node" >&2
    exit 1
fi
if [ ! -d "${SNAPSHOT_PATH}/database" ]; then
    echo "ours.sh: snapshot missing at ${SNAPSHOT_PATH}/database" >&2
    echo "         set SNAPSHOT_PATH or run bench/bootstrap.sh --only snapshot." >&2
    exit 1
fi
for f in "${PLAN}" "${LOADGEN}" "${EMIT}"; do
    [ -e "$f" ] || { echo "ours.sh: required file missing: $f" >&2; exit 1; }
done
if ! command -v python3 >/dev/null 2>&1; then
    echo "ours.sh: python3 is required (load generator + JSON emitter)." >&2
    exit 1
fi

# Refuse to clobber a tron-node already running against THIS bench data-dir.
# Bracket trick so pgrep never self-matches.
if pgrep -af '[t]ron-node' 2>/dev/null | grep -qF -- "${DATA_DIR}"; then
    echo "ours.sh: a tron-node is already running against ${DATA_DIR}." >&2
    echo "         stop it before re-running this benchmark." >&2
    exit 1
fi
# Refuse if the chosen HTTP port is already taken.
if command -v ss >/dev/null 2>&1 && ss -ltn 2>/dev/null | grep -qE "[: ]${HTTP_PORT}\b"; then
    echo "ours.sh: port ${HTTP_PORT} is already in use; set HTTP_PORT to a free port." >&2
    exit 1
fi

# Disk-space preflight: the copy duplicates the snapshot.
mkdir -p "${BENCH_WORK}"
snap_mib=$(du -sm "${SNAPSHOT_PATH}/database" 2>/dev/null | cut -f1)
free_mib=$(df -Pm "${BENCH_WORK}" 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${snap_mib:-}" ] && [ -n "${free_mib:-}" ]; then
    need_mib=$(( snap_mib + 2048 ))
    if [ "${free_mib}" -lt "${need_mib}" ]; then
        echo "ours.sh: not enough free space under BENCH_WORK for a snapshot copy." >&2
        echo "         snapshot ~${snap_mib} MiB, free ${free_mib} MiB, need ~${need_mib} MiB." >&2
        exit 1
    fi
fi

mkdir -p "${OUT}"
GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

RUN_LOG="${OUT}/rpc-ours.log"
SAMPLE_IDLE="${OUT}/rpc-ours.idle.sample"
SAMPLE_LOAD="${OUT}/rpc-ours.load.sample"
LOADGEN_OUT="${OUT}/rpc-ours.queries.json"
: > "${RUN_LOG}"

# ---------------------------------------------------------------------------
# Bench-specific config: serve HTTP only; sync/p2p/discovery OFF (static
# snapshot); gRPC + metrics off; constant-call support ON so the read-only
# triggerConstantContract query exercises the VM read path. Written fresh each
# run into BENCH_WORK so it never shadows the operator's ./config.toml.
# ---------------------------------------------------------------------------
BENCH_CONFIG="${BENCH_WORK}/ours-rpc-config.toml"
mkdir -p "$(dirname "${BENCH_CONFIG}")"
cat > "${BENCH_CONFIG}" <<EOF
# Generated by bench/rpc/ours.sh -- RPC/query benchmark config. Do not edit by
# hand; it is overwritten on every run. The node serves the HTTP /wallet/* API
# over the static snapshot with no sync and no peers.

[p2p]
discover_enable = false
listen = false

[http]
host = "${HTTP_HOST}"
port = ${HTTP_PORT}

[vm]
# Read-only constant calls (triggerConstantContract) -- the VM read path this
# dimension stresses. java-tron's equivalent is vm.supportConstant = true.
support_constant = true
EOF

# ---------------------------------------------------------------------------
# Cleanup: on any exit, stop the engine and any live sampler.
# ---------------------------------------------------------------------------
ENGINE_PID=""
SAMPLER_PID=""
cleanup() {
    bench_stop_sampler "${SAMPLER_PID}"
    if [ -n "${ENGINE_PID}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
        kill -TERM "${ENGINE_PID}" 2>/dev/null
        for _ in $(seq 1 30); do
            kill -0 "${ENGINE_PID}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "${ENGINE_PID}" 2>/dev/null
        wait "${ENGINE_PID}" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# ===========================================================================
# (a) Seed the bench data-dir by COPYING the snapshot. Timed as snapshot_load_s.
#
#     A plain recursive copy of the read-only snapshot into our writable bench
#     data-dir -- never a hard-link or reset of a shared directory. Both our
#     node and java open their stores at data_dir/database/<store>, so the copy
#     plants them 1:1. The source snapshot is never modified.
# ===========================================================================
echo "ours.sh: copying bench data-dir from snapshot..."
snap_start="$(bench_now_s)"
if ! bench_copy_snapshot "${SNAPSHOT_PATH}" "${DATA_DIR}"; then
    echo "ours.sh: snapshot copy failed." >&2
    exit 1
fi
snap_end="$(bench_now_s)"
SNAPSHOT_LOAD_S="$(bench_elapsed_s "${snap_start}" "${snap_end}")"
echo "ours.sh: snapshot copied in ${SNAPSHOT_LOAD_S}s"

# ===========================================================================
# (b) Start the node as a read-only query server (HTTP on, sync off).
# ===========================================================================
echo "ours.sh: starting query server (HTTP ${BASE_URL}, sync off)..."
RUST_LOG="${RUST_LOG:-info}" \
"${TRON_NODE}" start \
    --config "${BENCH_CONFIG}" \
    --data-dir "${DATA_DIR}" \
    --no-sync --no-rpc --no-grpc --no-metrics \
    >>"${RUN_LOG}" 2>&1 &
ENGINE_PID=$!

# ===========================================================================
# (c) Wait until the HTTP server answers the health query (getnowblock).
# ===========================================================================
healthy=no
for _ in $(seq 1 "${HEALTH_TIMEOUT_S}"); do
    if ! kill -0 "${ENGINE_PID}" 2>/dev/null; then
        echo "ours.sh: engine exited during startup; see ${RUN_LOG}" >&2
        tail -20 "${RUN_LOG}" >&2
        exit 1
    fi
    body="$(curl -s -m 3 -X POST "${BASE_URL}/wallet/getnowblock" 2>/dev/null)"
    if printf '%s' "${body}" | grep -q 'blockID'; then
        healthy=yes
        break
    fi
    sleep 1
done
if [ "${healthy}" != "yes" ]; then
    echo "ours.sh: HTTP server did not answer getnowblock within ${HEALTH_TIMEOUT_S}s." >&2
    tail -20 "${RUN_LOG}" >&2
    exit 1
fi
echo "ours.sh: server healthy."

# ===========================================================================
# (d) Steady-state IDLE RSS -- sample for IDLE_SAMPLE_S with NO load.
# ===========================================================================
echo "ours.sh: measuring steady-state idle RSS for ${IDLE_SAMPLE_S}s..."
: > "${SAMPLE_IDLE}"
SAMPLER_PID="$(bench_sample_proc "${ENGINE_PID}" "${SAMPLE_IDLE}")" || SAMPLER_PID=""
sleep "${IDLE_SAMPLE_S}"
bench_stop_sampler "${SAMPLER_PID}"
SAMPLER_PID=""
IDLE_SUMMARY="$(bench_sampler_summary "${SAMPLE_IDLE}")"
IDLE_RSS_MB="$(awk '{print $1}' <<<"${IDLE_SUMMARY}")"
IDLE_RSS_MB="${IDLE_RSS_MB:-0}"
echo "ours.sh: idle_rss_mb=${IDLE_RSS_MB}"

# ===========================================================================
# (e) Run the shared query plan through the shared load generator while
#     sampling peak RSS + CPU under load.
# ===========================================================================
echo "ours.sh: running query load plan (sampling peak RSS + CPU)..."
: > "${SAMPLE_LOAD}"
SAMPLER_PID="$(bench_sample_proc "${ENGINE_PID}" "${SAMPLE_LOAD}")" || SAMPLER_PID=""

python3 "${LOADGEN}" \
    --base-url "${BASE_URL}" \
    --plan "${PLAN}" \
    --out "${LOADGEN_OUT}" \
    >>"${RUN_LOG}" 2>&1
LOADGEN_RC=$?

bench_stop_sampler "${SAMPLER_PID}"
SAMPLER_PID=""

if [ "${LOADGEN_RC}" -ne 0 ] || [ ! -s "${LOADGEN_OUT}" ]; then
    echo "ours.sh: load generator failed (rc=${LOADGEN_RC}); see ${RUN_LOG}" >&2
    tail -20 "${RUN_LOG}" >&2
    exit 1
fi

LOAD_SUMMARY="$(bench_sampler_summary "${SAMPLE_LOAD}")"
PEAK_RSS_MB="$(awk '{print $1}' <<<"${LOAD_SUMMARY}")"
AVG_CPU_PCT="$(awk '{print $2}' <<<"${LOAD_SUMMARY}")"
PEAK_RSS_MB="${PEAK_RSS_MB:-0}"
AVG_CPU_PCT="${AVG_CPU_PCT:-0}"
echo "ours.sh: peak_rss_mb=${PEAK_RSS_MB} avg_cpu_pct=${AVG_CPU_PCT}"

# ===========================================================================
# (f) Stop the engine cleanly (trap cleanup also covers abnormal exits).
# ===========================================================================
kill -TERM "${ENGINE_PID}" 2>/dev/null
for _ in $(seq 1 30); do
    kill -0 "${ENGINE_PID}" 2>/dev/null || break
    sleep 1
done
kill -KILL "${ENGINE_PID}" 2>/dev/null
wait "${ENGINE_PID}" 2>/dev/null
ENGINE_PID=""

# ===========================================================================
# (g) Emit the RPC-dimension result JSON.
# ===========================================================================
NOTES="read-only query server over a copy of the snapshot; HTTP /wallet/* JSON \
API; sync/p2p off; vm.support_constant=true; no managed heap (native RSS = true \
working set, no JVM -Xmx); snapshot seeded by plain copy; same snapshot/plan/ \
protocol as java, run in isolation"

python3 "${EMIT}" \
    --out "${OUT}/rpc-ours.json" \
    --engine ours \
    --version "${GIT_SHA}" \
    --idle-rss-mb "${IDLE_RSS_MB}" \
    --peak-rss-mb "${PEAK_RSS_MB}" \
    --avg-cpu-pct "${AVG_CPU_PCT}" \
    --queries-json "${LOADGEN_OUT}" \
    --notes "${NOTES}"

echo "ours.sh: done -- wrote ${OUT}/rpc-ours.json"
