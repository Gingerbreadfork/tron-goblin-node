#!/usr/bin/env bash
# Benchmark tron-goblin-node against a peer in two phases:
#
#   Phase 1 (sync)    — clean data dir → catch up to --sync-blocks blocks.
#                       Throughput target: blocks-applied / wall-second.
#   Phase 2 (steady)  — keep running for --steady-mins minutes after phase 1.
#                       Steady-state CPU / RSS / disk growth.
#
# Every --sample-secs the script records one CSV row per phase containing:
#   timestamp, head, applied_total, peer_failures, reconnects, mempool_size,
#   cpu_pct, rss_kb, disk_kb, fd_count
#
# Output lands under --work-dir (default ./bench-work):
#
#   bench-work/
#     data/                       node state (wiped per run unless --keep-data)
#     node.log                    full tron-node stdout/stderr
#     sync.csv, steady.csv        per-phase samples
#     summary.txt                 human-readable comparison report
#
# Usage:
#   scripts/self-bench.sh PEER [options]
#
#   PEER                  Required. HOST:PORT of the peer to sync against.
#
# Options:
#   --sync-blocks N       Phase 1 target block count. Default 5000.
#   --steady-mins M       Phase 2 duration in minutes. Default 5.
#   --sample-secs S       Sample interval. Default 10.
#   --work-dir DIR        Where logs / data / CSV land. Default ./bench-work.
#   --rpc-port N          Default 8545.
#   --metrics-port N      Default 9090.
#   --log-level L         RUST_LOG value. Default "info".
#   --keep-data           Don't wipe the data dir before starting.
#   --release             Force a release rebuild before starting.
#   --startup-timeout S   Seconds to wait for /metrics to come up. Default 60.
#   --shutdown-grace S    SIGTERM → SIGKILL grace. Default 60.
#   -h, --help            Show this help.

set -euo pipefail

# --------------------------- defaults ---------------------------------

peer=""
sync_blocks=5000
steady_mins=5
sample_secs=10
work_dir="./bench-work"
rpc_port=8545
metrics_port=9090
log_level="info"
keep_data=0
force_release_build=0
startup_timeout=60
shutdown_grace=60

# --------------------------- arg parse --------------------------------

usage() {
    sed -n '2,/^set -euo pipefail/p' "$0" | sed '/^set -euo pipefail/d; s/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)         usage; exit 0 ;;
        --sync-blocks)     sync_blocks="$2"; shift 2 ;;
        --steady-mins)     steady_mins="$2"; shift 2 ;;
        --sample-secs)     sample_secs="$2"; shift 2 ;;
        --work-dir)        work_dir="$2"; shift 2 ;;
        --rpc-port)        rpc_port="$2"; shift 2 ;;
        --metrics-port)    metrics_port="$2"; shift 2 ;;
        --log-level)       log_level="$2"; shift 2 ;;
        --keep-data)       keep_data=1; shift ;;
        --release)         force_release_build=1; shift ;;
        --startup-timeout) startup_timeout="$2"; shift 2 ;;
        --shutdown-grace)  shutdown_grace="$2"; shift 2 ;;
        --)                shift; break ;;
        -*)
            echo "ERROR: unknown option: $1" >&2
            echo "Try '$0 --help'." >&2
            exit 2
            ;;
        *)
            if [ -z "$peer" ]; then
                peer="$1"; shift
            else
                echo "ERROR: positional PEER already given as '$peer'; extra arg: $1" >&2
                exit 2
            fi
            ;;
    esac
done

if [ -z "$peer" ]; then
    echo "ERROR: PEER argument is required (HOST:PORT)." >&2
    echo "Try '$0 --help'." >&2
    exit 2
fi

peer_host="${peer%%:*}"
peer_port="${peer##*:}"
if [ "$peer_host" = "$peer_port" ] || [ -z "$peer_host" ] || [ -z "$peer_port" ]; then
    echo "ERROR: PEER must be HOST:PORT (got '$peer')." >&2
    exit 2
fi

# --------------------------- pre-flight -------------------------------

# Resolve --work-dir against the caller's CWD, not the repo root. Otherwise
# `cd /tmp && bench.sh peer` with default --work-dir surprisingly writes
# into <repo>/bench-work/ instead of /tmp/bench-work/.
case "$work_dir" in
    /*) ;;                                          # already absolute
    *)  work_dir="$PWD/$work_dir" ;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# Two layouts to support: a release bundle, which puts tron-node at the
# bundle root one level up from this script and carries no sources; and a
# source checkout, which builds into target/release.
binary=""
for cand in "$repo_root/tron-node" "$repo_root/target/release/tron-node"; do
    if [ -x "$cand" ]; then binary="$cand"; break; fi
done
if [ -z "$binary" ] || [ "$force_release_build" -eq 1 ]; then
    if [ -f "$repo_root/Cargo.toml" ]; then
        echo "==> Building tron-node (release)…"
        cargo build --release --bin tron-node
        binary="$repo_root/target/release/tron-node"
    elif [ -z "$binary" ]; then
        echo "ERROR: no 'tron-node' binary found at $repo_root, and no sources to build one." >&2
        exit 1
    else
        echo "==> No sources here; using the bundled $binary." >&2
    fi
fi

mkdir -p "$work_dir"
work_dir="$(cd "$work_dir" && pwd)"      # canonicalise
data_dir="$work_dir/data"
log_file="$work_dir/node.log"
sync_csv="$work_dir/sync.csv"
steady_csv="$work_dir/steady.csv"
summary="$work_dir/summary.txt"

if [ "$keep_data" -eq 0 ] && [ -e "$data_dir" ]; then
    echo "==> Wiping $data_dir for a fresh-from-genesis run (pass --keep-data to skip)."
    rm -rf "$data_dir"
fi

echo "==> Pinging peer $peer (TCP, 3s)…"
if ! timeout 3 bash -c ">/dev/tcp/$peer_host/$peer_port" 2>/dev/null; then
    echo "ERROR: TCP connect to $peer failed within 3s." >&2
    echo "       Check the peer is up, the port is right (TRON P2P 18888 by default)," >&2
    echo "       and no firewall is in the way." >&2
    exit 1
fi

# Header row written once per CSV.
csv_header="ts,head,applied_total,peer_failures,reconnects,mempool,cpu_pct,rss_kb,disk_kb,fds"
echo "$csv_header" > "$sync_csv"
echo "$csv_header" > "$steady_csv"

# --------------------------- helpers ----------------------------------

CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)

# Pull a Prometheus gauge / counter value by exact metric name. Tolerates
# labels (`name{...} value`). Returns the FIRST matching value, or "" if
# the metric isn't present yet (the node may emit metrics lazily).
metric() {
    local name=$1
    local body=$2
    awk -v n="$name" '
        index($0, "#") == 1 { next }                # skip HELP/TYPE comments
        $0 ~ "^" n "([{ ])" {
            # Value is the last whitespace-separated numeric token on the line.
            for (i = NF; i >= 1; i--) {
                if ($i ~ /^[-+0-9eE.]+$/) { print $i; exit }
            }
        }
    ' <<<"$body"
}

# Delta-based CPU sampler. `ps -o %cpu` reports the cumulative average since
# process start, which strictly trends toward the long-run average and is
# the wrong shape for benchmarking — replace it with a proper /proc-driven
# delta. State lives in globals so we can survive being called from
# successive iterations.
LAST_CPU_JIFFIES=
LAST_CPU_NS=
LAST_CPU=0.0
LAST_RSS=0

update_resources() {
    local pid=$1
    local stat rest utime stime jiffies now_ns
    if ! stat=$(cat /proc/"$pid"/stat 2>/dev/null); then
        LAST_CPU=0.0
        LAST_RSS=0
        return
    fi
    # The `comm` field is in parens and may contain spaces; strip up to the
    # final `) ` before field-splitting the rest.
    rest=${stat##*) }
    local -a fields
    read -ra fields <<<"$rest"
    # After `) `, fields are: state ppid pgrp session tty_nr tpgid flags
    # minflt cminflt majflt cmajflt utime stime ... → utime=[11], stime=[12]
    utime=${fields[11]:-0}
    stime=${fields[12]:-0}
    jiffies=$((utime + stime))
    now_ns=$(date +%s%N)
    if [ -n "$LAST_CPU_JIFFIES" ] && [ -n "$LAST_CPU_NS" ]; then
        LAST_CPU=$(awk -v nj="$jiffies" -v pj="$LAST_CPU_JIFFIES" \
                       -v nt="$now_ns" -v pt="$LAST_CPU_NS" -v tck="$CLK_TCK" '
            BEGIN {
                dt = (nt - pt) / 1e9
                if (dt <= 0) { print "0.0"; exit }
                printf "%.1f", (nj - pj) / tck / dt * 100
            }')
    else
        LAST_CPU=0.0
    fi
    LAST_CPU_JIFFIES=$jiffies
    LAST_CPU_NS=$now_ns
    LAST_RSS=$(awk '/^VmRSS:/ { print $2; exit }' /proc/"$pid"/status 2>/dev/null || echo 0)
    LAST_RSS=${LAST_RSS:-0}
}

# One CSV row of samples. Returns 1 if the node process has died.
sample() {
    local pid=$1
    local csv=$2
    local ts; ts=$(date +%s)

    if ! kill -0 "$pid" 2>/dev/null; then
        return 1
    fi

    local body
    body=$(curl -s --max-time 5 "http://127.0.0.1:$metrics_port/metrics" || true)

    local head applied peer_fail reconnects mempool
    head=$(metric tron_node_head_block_number "$body")
    applied=$(metric tron_node_sync_blocks_applied_total "$body")
    peer_fail=$(metric tron_node_sync_peer_failures_total "$body")
    reconnects=$(metric tron_node_sync_reconnects_total "$body")
    mempool=$(metric tron_node_mempool_size "$body")

    update_resources "$pid"

    local disk fds
    disk=$(du -sk "$data_dir" 2>/dev/null | awk '{print $1}')
    disk=${disk:-0}
    fds=$(find /proc/"$pid"/fd -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$ts" "${head:-0}" "${applied:-0}" "${peer_fail:-0}" \
        "${reconnects:-0}" "${mempool:-0}" "$LAST_CPU" "$LAST_RSS" "$disk" "$fds" \
        >> "$csv"
    return 0
}

stop_node() {
    local pid=$1
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    echo "==> Stopping node (pid $pid, SIGTERM, ${shutdown_grace}s grace)…"
    kill -TERM "$pid" 2>/dev/null || true
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt "$shutdown_grace" ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "==> Grace expired, sending SIGKILL."
        kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
}

# --------------------------- launch -----------------------------------

cat <<EOF

==> Starting tron-node
    peer       : $peer
    work dir   : $work_dir
    data dir   : $data_dir
    sync target: $sync_blocks blocks
    steady     : ${steady_mins} min
    sample     : ${sample_secs} s
    RPC        : http://127.0.0.1:$rpc_port
    metrics    : http://127.0.0.1:$metrics_port/metrics
    log        : $log_file

EOF

RUST_LOG="$log_level" "$binary" start \
    --data-dir "$data_dir" \
    --peer "$peer" \
    --rpc-port "$rpc_port" \
    --metrics-port "$metrics_port" \
    > "$log_file" 2>&1 &
node_pid=$!

trap 'stop_node "$node_pid"' EXIT INT TERM

# Wait for /metrics to start serving (RocksDB open + bootstrap can take a bit).
echo "==> Waiting up to ${startup_timeout}s for /metrics to come up…"
waited=0
until curl -s --max-time 2 "http://127.0.0.1:$metrics_port/metrics" >/dev/null 2>&1; do
    if ! kill -0 "$node_pid" 2>/dev/null; then
        echo "ERROR: node died during startup. Tail of $log_file:" >&2
        tail -40 "$log_file" >&2
        exit 1
    fi
    if [ "$waited" -ge "$startup_timeout" ]; then
        echo "ERROR: /metrics never came up within ${startup_timeout}s." >&2
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
done
echo "==> /metrics live after ${waited}s."

# --------------------------- phase 1: sync ----------------------------

echo
echo "==> Phase 1: sync to block $sync_blocks"
phase1_start=$(date +%s)
while :; do
    sleep "$sample_secs"
    if ! sample "$node_pid" "$sync_csv"; then
        echo "ERROR: node died during sync phase." >&2
        exit 1
    fi
    last=$(tail -1 "$sync_csv")
    head=$(cut -d, -f2 <<<"$last")
    elapsed=$(( $(date +%s) - phase1_start ))
    printf '    [sync   t=%5ds] head=%-10s applied=%s\n' \
        "$elapsed" "$head" "$(cut -d, -f3 <<<"$last")"
    # Float-tolerant comparison: bash -ge would choke on "5.0e3" etc.
    if awk -v h="${head:-0}" -v t="$sync_blocks" 'BEGIN { exit !(h+0 >= t+0) }'; then
        break
    fi
done
phase1_end=$(date +%s)

# --------------------------- phase 2: steady --------------------------

echo
echo "==> Phase 2: steady-state for ${steady_mins} min"
phase2_start=$(date +%s)
phase2_deadline=$(( phase2_start + steady_mins * 60 ))
while :; do
    sleep "$sample_secs"
    if ! sample "$node_pid" "$steady_csv"; then
        echo "ERROR: node died during steady phase." >&2
        exit 1
    fi
    last=$(tail -1 "$steady_csv")
    elapsed=$(( $(date +%s) - phase2_start ))
    printf '    [steady t=%5ds] head=%-10s cpu=%s%% rss=%sMB disk=%sMB\n' \
        "$elapsed" \
        "$(cut -d, -f2 <<<"$last")" \
        "$(cut -d, -f7 <<<"$last")" \
        "$(awk -F, '{printf "%.0f", $8/1024}' <<<"$last")" \
        "$(awk -F, '{printf "%.0f", $9/1024}' <<<"$last")"
    if [ "$(date +%s)" -ge "$phase2_deadline" ]; then
        break
    fi
done
phase2_end=$(date +%s)

# Drop the trap so we can shut down deliberately and still write the summary.
trap - EXIT INT TERM
stop_node "$node_pid"

# --------------------------- summary ----------------------------------

# All math is done in awk on the CSV files — no bash floating point. The
# first non-header row anchors the (t0,h0,d0) baseline; every row (including
# that first one) folds into the CPU/RSS aggregates. Single-sample phases
# print "insufficient samples" instead of dividing by zero.
summarise_phase() {
    local csv=$1
    awk -F, '
    NR == 1 { next }                              # header
    {
        if (n == 0) { t0=$1; h0=$2; d0=$9 }
        t1=$1; h1=$2; d1=$9
        cpu = $7 + 0; rss = $8 + 0; disk = $9 + 0
        if (cpu > cpu_peak) cpu_peak = cpu
        if (rss > rss_peak) rss_peak = rss
        if (disk > disk_peak) disk_peak = disk
        cpu_sum += cpu; rss_sum += rss; n++
    }
    END {
        if (n < 2) {
            print "  (insufficient samples — phase ran for less than 2 sample intervals)"
            exit
        }
        dur = t1 - t0
        bps = (dur > 0) ? (h1 - h0) / dur : 0
        printf "  duration              : %ds\n", dur
        printf "  blocks                : %d (head %d → %d)\n", h1 - h0, h0, h1
        printf "  throughput            : %.2f blocks/sec\n", bps
        printf "  CPU avg / peak        : %.1f%% / %.1f%%\n", cpu_sum/n, cpu_peak
        printf "  RSS avg / peak        : %.0f MB / %.0f MB\n", rss_sum/n/1024, rss_peak/1024
        printf "  disk start → end      : %.0f MB → %.0f MB (Δ %.0f MB)\n", d0/1024, d1/1024, (d1-d0)/1024
        printf "  disk peak             : %.0f MB\n", disk_peak/1024
    }' "$csv"
}

{
    printf '%s\n' "tron-goblin-node benchmark $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  peer       : %s\n' "$peer"
    printf '  binary     : %s\n' "$binary"
    printf '  sync target: %d blocks\n' "$sync_blocks"
    printf '  steady     : %d min\n' "$steady_mins"
    printf '  sample     : %ds\n' "$sample_secs"
    echo
    echo "Phase 1 — sync"
    summarise_phase "$sync_csv"
    echo
    echo "Phase 2 — steady-state"
    summarise_phase "$steady_csv"
    echo
    printf 'Artifacts: %s\n' "$work_dir"
} | tee "$summary"
