#!/usr/bin/env bash
#
# ours.sh — tron-goblin-node ("ours") runner for the "vs java-tron" block-sync
# performance benchmark.
#
# PEER-SYNCS a fixed block range the SAME way java.sh does, starting from the
# SAME snapshot pre-state (a private, writable COPY of the user-supplied
# read-only snapshot), on the SAME machine, and measures block-apply throughput,
# peak memory, and CPU. report.py consumes the JSON both runners emit.
#
# Sync mechanism: `tron-node start [--peer SYNC_PEER] --max-blocks N` against a
# DEDICATED bench data-dir copied from the snapshot. This is the production sync
# + block-apply path — every block is fetched over p2p, validated, and executed
# against real snapshot state (accounts, contracts, resource weights), which is
# exactly what is being benchmarked.
#
# Symmetry / fairness: both engines do the SAME work the SAME way — sync the
# same range from the same source (SYNC_PEER, or public discovery when SYNC_PEER
# is empty), from the same snapshot pre-state, on the same box, run in series.
# The network path is identical for both, so it cancels out of the comparison;
# the timed window is the sync of [FROM, TO] only, with snapshot load reported
# separately as snapshot_load_s.
#
# Block-STM: the bench config enables `vm.parallel_exec = true` (our parallel
# block-execution path), the throughput strength this benchmark exists to show.
#
# ISOLATION: this only ever READS the snapshot at SNAPSHOT_PATH (copied into a
# BENCH_WORK data-dir it owns) and writes under BENCH_WORK. It never touches any
# shared/external directory. All inputs come from bench.config.

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
usage: bench/ours.sh [--from N] [--to N] [--out DIR]

  --from N   first block to apply   (default ${FROM})
  --to N     last block to apply    (default ${TO})
  --out DIR  results directory      (default ${OUT})

Syncs [--from, --to] on top of a copy of SNAPSHOT_PATH and emits a metric JSON
via lib.sh's bench_emit_json. Reproduces the "ours" half of the vs-java-tron
block-sync benchmark. All paths/peers come from bench/bench.config (override by
environment: SNAPSHOT_PATH, BENCH_WORK, SYNC_PEER, TRON_NODE, ...).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM="${2:?--from needs N}"; shift 2 ;;
        --to)   TO="${2:?--to needs N}";     shift 2 ;;
        --out)  OUT="${2:?--out needs DIR}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "ours.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ "${FROM}" -gt "${TO}" ]; then
    echo "ours.sh: --from (${FROM}) must be <= --to (${TO})" >&2
    exit 2
fi
BLOCKS=$(( TO - FROM + 1 ))
SNAPSHOT_HEAD=$(( FROM - 1 ))

# Dedicated bench data-dir (a writable COPY of the snapshot), under BENCH_WORK.
DATA_DIR="${SYNC_OURS_DATA}"

# ---------------------------------------------------------------------------
# Guards: fail fast and clearly before touching anything.
# ---------------------------------------------------------------------------

if [ ! -x "${TRON_NODE}" ]; then
    echo "ours.sh: ${TRON_NODE} not found or not executable." >&2
    echo "         build it first: bench/bootstrap.sh --only node" >&2
    exit 1
fi

# Snapshot present? Its stores live under <snapshot>/database.
if [ ! -d "${SNAPSHOT_PATH}/database" ]; then
    echo "ours.sh: snapshot missing at ${SNAPSHOT_PATH}/database" >&2
    echo "         set SNAPSHOT_PATH to a LiteFullNode snapshot, or run" >&2
    echo "         bench/bootstrap.sh --only snapshot (with SNAPSHOT_URL)." >&2
    exit 1
fi

# Refuse to clobber a tron-node already running against THIS bench data-dir.
# Bracket trick so pgrep never matches THIS script's own command line.
if pgrep -af '[t]ron-node' 2>/dev/null | grep -qF -- "${DATA_DIR}"; then
    echo "ours.sh: a tron-node is already running against ${DATA_DIR}." >&2
    echo "         stop it before re-running this benchmark." >&2
    exit 1
fi

# Disk-space preflight: the copy duplicates the snapshot. Require the snapshot's
# size (in MiB) free on the BENCH_WORK filesystem, with a small margin.
mkdir -p "${BENCH_WORK}"
snap_mib=$(du -sm "${SNAPSHOT_PATH}/database" 2>/dev/null | cut -f1)
free_mib=$(df -Pm "${BENCH_WORK}" 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "${snap_mib:-}" ] && [ -n "${free_mib:-}" ]; then
    need_mib=$(( snap_mib + 2048 ))
    if [ "${free_mib}" -lt "${need_mib}" ]; then
        echo "ours.sh: not enough free space under BENCH_WORK for a snapshot copy." >&2
        echo "         snapshot ~${snap_mib} MiB, free ${free_mib} MiB, need ~${need_mib} MiB." >&2
        echo "         point BENCH_WORK at a bigger disk." >&2
        exit 1
    fi
fi

mkdir -p "${OUT}"
export BENCH_OUT_DIR="${OUT}"

GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# Per-run log + metrics-sample files.
RUN_LOG="${OUT}/ours-${FROM}-${TO}.log"
SAMPLE_OUT="${OUT}/ours-${FROM}-${TO}.sample"
: > "${RUN_LOG}"
: > "${SAMPLE_OUT}"

# ---------------------------------------------------------------------------
# Bench-specific config: parallel block execution ON; all serving subsystems
# off (RPC/HTTP/gRPC/metrics). Discovery stays ON only when no SYNC_PEER is
# pinned (so the node can find public peers); when SYNC_PEER is set, discovery
# is off and the run is pinned to that single peer. Written fresh each run into
# BENCH_WORK so it never shadows the operator's ./config.toml.
# ---------------------------------------------------------------------------
BENCH_CONFIG="${BENCH_WORK}/ours-sync-config.toml"
mkdir -p "$(dirname "${BENCH_CONFIG}")"
if [ -n "${SYNC_PEER}" ]; then
    DISCOVER="false"
else
    DISCOVER="true"
fi
cat > "${BENCH_CONFIG}" <<EOF
# Generated by bench/ours.sh — block-sync benchmark config. Do not edit by
# hand; it is overwritten on every run.

[p2p]
# Discovery is off only when a single SYNC_PEER is pinned (throughput then
# reflects apply, not peer churn); otherwise on so the node finds public peers.
discover_enable = ${DISCOVER}
# Don't accept inbound peers during the bench.
listen = false

[vm]
# Our parallel block-execution path — the throughput strength being measured.
parallel_exec = true
EOF

# ---------------------------------------------------------------------------
# Cleanup: on any exit, make sure the engine is stopped and the sampler is gone.
# ---------------------------------------------------------------------------
ENGINE_PID=""
SAMPLER_PID=""
cleanup() {
    bench_stop_sampler "${SAMPLER_PID}"
    if [ -n "${ENGINE_PID}" ] && kill -0 "${ENGINE_PID}" 2>/dev/null; then
        # Graceful: the daemon stops sync + flushes RocksDB on SIGTERM.
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
# (a) Prepare the data-dir from the snapshot. Timed as snapshot_load_s.
#     --mode copy is the only safe choice: it duplicates the snapshot into our
#     writable bench data-dir (move would consume the source, symlink would let
#     block-apply WRITE into the source's SST dir). --force replaces any stale
#     bench data-dir. The source snapshot is opened read-only and never touched.
# ===========================================================================
echo "ours.sh: preparing bench data-dir from snapshot (copy)…"
rm -rf "${DATA_DIR}"
mkdir -p "${DATA_DIR}"

snap_start=$(date +%s.%N)
if ! "${TRON_NODE}" import-snapshot \
        --from "${SNAPSHOT_PATH}" \
        --data-dir "${DATA_DIR}" \
        --mode copy \
        --force >>"${RUN_LOG}" 2>&1; then
    echo "ours.sh: import-snapshot failed; see ${RUN_LOG}" >&2
    exit 1
fi
snap_end=$(date +%s.%N)
SNAPSHOT_LOAD_S=$(awk -v a="${snap_start}" -v b="${snap_end}" 'BEGIN{printf "%.1f", b-a}')

# Sanity: the imported head must sit at (from - 1) so the apply lands on `to`.
imported_head=$(grep -oE 'head block number:[[:space:]]+[0-9]+' "${RUN_LOG}" \
                | grep -oE '[0-9]+$' | tail -1)
if [ -n "${imported_head:-}" ] && [ "${imported_head}" != "${SNAPSHOT_HEAD}" ]; then
    echo "ours.sh: WARNING — imported head #${imported_head}, expected #${SNAPSHOT_HEAD}." >&2
    echo "         the snapshot height does not match --from ${FROM}; set FROM to" >&2
    echo "         (snapshot_head + 1) so both engines compare over the same range." >&2
fi
echo "ours.sh: snapshot loaded in ${SNAPSHOT_LOAD_S}s (head #${imported_head:-unknown})"

# ===========================================================================
# (b) Start the engine to sync [from, to]. --max-blocks caps applied blocks at
#     exactly BLOCKS; on hitting the cap the node logs "max_blocks cap reached;
#     exiting" and exits cleanly. Serving subsystems are off (config + flags).
#     A pinned --peer is passed only when SYNC_PEER is set; otherwise the node
#     discovers public peers. The apply-phase clock starts here and excludes
#     snapshot_load_s.
# ===========================================================================
PEER_ARGS=()
PEER_DESC="public discovery"
if [ -n "${SYNC_PEER}" ]; then
    PEER_ARGS=(--peer "${SYNC_PEER}")
    PEER_DESC="${SYNC_PEER}"
fi
echo "ours.sh: syncing ${BLOCKS} blocks [#${FROM} … #${TO}] via ${PEER_DESC}…"
apply_start=$(date +%s.%N)

RUST_LOG="${RUST_LOG:-info}" \
"${TRON_NODE}" start \
    --config "${BENCH_CONFIG}" \
    --data-dir "${DATA_DIR}" \
    "${PEER_ARGS[@]}" \
    --max-blocks "${BLOCKS}" \
    --progress-log-interval 1000 \
    --no-rpc --no-http --no-grpc --no-metrics \
    >>"${RUN_LOG}" 2>&1 &
ENGINE_PID=$!

# ---------------------------------------------------------------------------
# (c) Sample peak RSS + avg CPU of the engine pid via lib.sh's bench_sample_proc.
# ---------------------------------------------------------------------------
SAMPLER_PID="$(bench_sample_proc "${ENGINE_PID}" "${SAMPLE_OUT}")" || SAMPLER_PID=""

# ---------------------------------------------------------------------------
# (d) Detect completion. Primary signal: the engine process exits on its own
#     when the --max-blocks cap is hit. Belt-and-braces: a watchdog also greps
#     the log for the cap line and stops the engine if it lingers.
# ---------------------------------------------------------------------------
(
    while kill -0 "${ENGINE_PID}" 2>/dev/null; do
        if grep -q "max_blocks cap reached" "${RUN_LOG}" 2>/dev/null; then
            sleep 2
            kill -0 "${ENGINE_PID}" 2>/dev/null && kill -TERM "${ENGINE_PID}" 2>/dev/null
            break
        fi
        sleep 2
    done
) &
WATCHDOG_PID=$!

# Block until the engine exits (cap reached, or watchdog stopped it).
wait "${ENGINE_PID}" 2>/dev/null
ENGINE_RC=$?
apply_end=$(date +%s.%N)
ENGINE_PID=""   # reaped; stop cleanup() from re-killing.

kill "${WATCHDOG_PID}" 2>/dev/null
wait "${WATCHDOG_PID}" 2>/dev/null

# Stop the sampler (it also exits on its own when the engine pid dies).
bench_stop_sampler "${SAMPLER_PID}"
SAMPLER_PID=""

# (f) wall_clock_s for the apply phase ONLY (excludes snapshot_load_s).
WALL_S=$(awk -v a="${apply_start}" -v b="${apply_end}" 'BEGIN{printf "%.1f", b-a}')

# Confirm the cap actually fired — otherwise the run is not comparable.
CAP_REACHED=no
if grep -q "max_blocks cap reached" "${RUN_LOG}" 2>/dev/null; then
    CAP_REACHED=yes
fi

# Reduce the sampler CSV to peak RSS + avg CPU.
SUMMARY="$(bench_sampler_summary "${SAMPLE_OUT}")"
PEAK_RSS_MB="$(awk '{print $1}' <<<"${SUMMARY}")"
AVG_CPU_PCT="$(awk '{print $2}' <<<"${SUMMARY}")"
PEAK_RSS_MB="${PEAK_RSS_MB:-0}"
AVG_CPU_PCT="${AVG_CPU_PCT:-0}"

# ---------------------------------------------------------------------------
# Notes: record the sync mechanism + run conditions for report.py / humans.
# ---------------------------------------------------------------------------
NOTES="peer-sync via ${PEER_DESC} (same source/snapshot/range as java); vm.parallel_exec=true (Block-STM); snapshot=copy-mode import; max_blocks=${BLOCKS} cap_reached=${CAP_REACHED} engine_rc=${ENGINE_RC}"

# (g) Emit the metric JSON via lib.sh.
bench_emit_json \
    ours \
    "${GIT_SHA}" \
    "${FROM}" \
    "${TO}" \
    "${SNAPSHOT_LOAD_S}" \
    "${WALL_S}" \
    "${PEAK_RSS_MB}" \
    "${AVG_CPU_PCT}" \
    "${NOTES}"

echo "ours.sh: done — ${BLOCKS} blocks in ${WALL_S}s (snapshot load ${SNAPSHOT_LOAD_S}s)."
if [ "${CAP_REACHED}" != "yes" ]; then
    echo "ours.sh: WARNING — max_blocks cap line not seen in log; the range may be" >&2
    echo "         incomplete. Inspect ${RUN_LOG}." >&2
    exit 1
fi
