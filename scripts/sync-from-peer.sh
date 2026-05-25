#!/usr/bin/env bash
# Sync tron-goblin-node against a single peer of your choice — typically
# a java-tron node you run yourself. Useful for end-to-end testing
# without the noise of the public-mainnet seed list, and for catching
# wire / sync-protocol issues before they hit the wild.
#
# Usage:
#
#   ./scripts/sync-from-peer.sh PEER [options]
#
#   PEER                Required. HOST:PORT of the peer to sync against.
#                       Default TRON P2P port is 18888.
#
# Options:
#
#   --max-blocks N      Stop after applying N blocks. Default 100.
#   --data-dir DIR      Where chain state lives. Default ./sync-test-data.
#   --keep-data         Don't wipe the data dir before starting. Default
#                       is to start from genesis.
#   --rpc-port N        JSON-RPC port. Default 8545.
#   --metrics-port N    Prometheus port. Default 9090.
#   --log-level L       RUST_LOG value. Default "info". Try
#                       "info,tron_node::sync=debug" to inspect the
#                       sync exchange in detail (very chatty).
#   --log-file FILE     Tee node output here for post-run analysis.
#                       Default ./sync-from-peer.log.
#   --release           Force a release-mode rebuild before starting.
#   -h, --help          Show this help and exit.
#
# Examples:
#
#   # 100-block smoke test against a node on the same LAN.
#   ./scripts/sync-from-peer.sh 192.168.0.36:18888
#
#   # 100K-block endurance run with debug-level sync logging.
#   ./scripts/sync-from-peer.sh 192.168.0.36:18888 \
#       --max-blocks 100000 \
#       --log-level info,tron_node::sync=debug
#
# Once the daemon is running, you can watch progress in another
# terminal with:
#
#   watch -n 5 'curl -s http://127.0.0.1:9090/metrics | \
#       grep -E "tron_node_(head_block_number|sync_blocks_applied_total|sync_peer_failures_total|sync_reconnects_total) "'

set -euo pipefail

# --------------------------- defaults ---------------------------------

max_blocks=100
data_dir="./sync-test-data"
keep_data=0
rpc_port=8545
metrics_port=9090
log_level="info"
log_file="./sync-from-peer.log"
force_release_build=0
peer=""

# --------------------------- arg parse --------------------------------

usage() {
    # Print the leading comment block (between the shebang and the first
    # blank line that follows `set -e`). Keeps usage text in one place.
    sed -n '2,/^set -euo pipefail/p' "$0" | sed '/^set -euo pipefail/d; s/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --max-blocks)  max_blocks="$2"; shift 2 ;;
        --data-dir)    data_dir="$2"; shift 2 ;;
        --keep-data)   keep_data=1; shift ;;
        --rpc-port)    rpc_port="$2"; shift 2 ;;
        --metrics-port) metrics_port="$2"; shift 2 ;;
        --log-level)   log_level="$2"; shift 2 ;;
        --log-file)    log_file="$2"; shift 2 ;;
        --release)     force_release_build=1; shift ;;
        --)            shift; break ;;
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

# Split host:port for the reachability pre-flight below.
peer_host="${peer%%:*}"
peer_port="${peer##*:}"
if [ "$peer_host" = "$peer_port" ] || [ -z "$peer_host" ] || [ -z "$peer_port" ]; then
    echo "ERROR: PEER must be HOST:PORT (got '$peer')." >&2
    exit 2
fi

# --------------------------- pre-flight -------------------------------

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

binary="$repo_root/target/release/tron-node"
if [ ! -x "$binary" ] || [ "$force_release_build" -eq 1 ]; then
    echo "==> Building tron-node (release)…"
    cargo build --release --bin tron-node
fi

# TCP reachability check. /dev/tcp is a bash builtin — no `nc` required.
echo "==> Pinging peer $peer (TCP connect, 3s timeout)…"
if ! timeout 3 bash -c ">/dev/tcp/$peer_host/$peer_port" 2>/dev/null; then
    cat >&2 <<EOF
WARNING: couldn't open TCP connection to $peer within 3s.

This is not fatal — the daemon will retry with backoff — but if it
keeps failing, check:

  * The peer is actually running and listening on $peer_port.
  * No firewall (host or network) is between you and it.
  * Default java-tron P2P port is 18888, NOT the JSON-RPC port (8545)
    or the gRPC port (50051). Make sure you've passed the P2P port.

EOF
fi

if [ "$keep_data" -eq 0 ] && [ -e "$data_dir" ]; then
    echo "==> Removing $data_dir for a fresh-from-genesis run (pass --keep-data to skip)."
    rm -rf "$data_dir"
fi

# --------------------------- run --------------------------------------

cat <<EOF

==> Starting tron-node
    peer       : $peer
    data dir   : $data_dir
    max blocks : $max_blocks
    RPC        : http://127.0.0.1:$rpc_port
    metrics    : http://127.0.0.1:$metrics_port/metrics
    log file   : $log_file
    log level  : $log_level

    Live metrics watch (another terminal):
      watch -n 5 'curl -s http://127.0.0.1:$metrics_port/metrics | \\
          grep -E "tron_node_(head_block_number|sync_blocks_applied_total|sync_peer_failures_total|sync_reconnects_total) "'

EOF

RUST_LOG="$log_level" "$binary" start \
    --data-dir "$data_dir" \
    --peer "$peer" \
    --max-blocks "$max_blocks" \
    --rpc-port "$rpc_port" \
    --metrics-port "$metrics_port" \
    2>&1 | tee "$log_file"

# --------------------------- post-run summary -------------------------

cat <<EOF

==> Run finished. Quick summary from $log_file:

EOF

applied=$(grep -c "block applied" "$log_file" 2>/dev/null || echo 0)
disconnects=$(grep -cE "app-disconnected|peer failed" "$log_file" 2>/dev/null || echo 0)
echo "  blocks applied             : $applied"
echo "  peer failure / disconnect  : $disconnects"
echo
echo "  last 3 'block applied' lines:"
grep "block applied" "$log_file" 2>/dev/null | tail -3 | sed 's/^/    /' || true
echo
echo "  any reorg / fork-tree weirdness:"
grep -E "REORG|side fork|rejected" "$log_file" 2>/dev/null | head -5 | sed 's/^/    /' || true
echo
