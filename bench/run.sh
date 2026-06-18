#!/usr/bin/env bash
#
# bench/run.sh -- orchestrator for the "tron-goblin-node vs java-tron"
# multi-dimension benchmark.
#
# The suite measures three independent dimensions, each with its own pair of
# per-engine runners:
#
#   sync    bench/ours.sh        / bench/java.sh        (--from N --to N --out DIR)
#   decode  bench/decode/ours.sh / bench/decode/java.sh (--count N --out DIR)
#   rpc     bench/rpc/ours.sh    / bench/rpc/java.sh     (--out DIR)
#
# For each selected dimension this script invokes that dimension's ours + java
# runner, in series (each pins the machine), passing the arguments that runner
# expects. Every runner writes its own results JSON into the results dir. Once
# all selected runners have completed, bench/report.py reads every
# bench/results/*.json and produces a single bench/results/REPORT.md.
#
# This script is intentionally engine- and dimension-agnostic about the work
# itself: the apply/decode/serve mechanism, snapshot reset, and version stamping
# all live in the per-engine runners. run.sh only selects dimensions, wires
# arguments through, enforces that the shared inputs exist, and reduces the
# per-engine JSON to a report.
#
# USAGE
#   bench/run.sh [--from N] [--to N] [--engines ours,java] \
#                [--dimensions sync,rpc,decode] [--count N] [--out DIR]
#
#   --from N           first block to sync (sync dimension; default from config)
#   --to N             last block to sync, inclusive (default from config)
#   --count N          decode-corpus block count (decode dimension; default from config)
#   --engines LIST     comma-separated subset of {ours,java} (default: both)
#   --dimensions LIST  comma-separated subset of {sync,rpc,decode} (default: all)
#   --out DIR          results directory (default: bench/results)
#   -h, --help         show this help
#
# Defaults (FROM/TO/DECODE_COUNT and every path/peer) come from
# bench/bench.config and are overridable by environment. The default sync range
# expects the supplied snapshot's head to sit at (FROM - 1). See bench/README.md
# (and the per-dimension bench/decode/README.md, bench/rpc/README.md) for the
# full methodology, fairness notes, and caveats.
set -uo pipefail

# ---------------------------------------------------------------------------
# Locate ourselves and the repo root so the script works from any CWD.
# ---------------------------------------------------------------------------
BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
export BENCH_DIR
REPO_ROOT="$(cd "$BENCH_DIR/.." && pwd)"
export REPO_ROOT

# shellcheck source=bench/lib.sh
. "$BENCH_DIR/lib.sh"
# shellcheck source=bench/bench.config
. "$BENCH_DIR/bench.config"

# ---------------------------------------------------------------------------
# Defaults (block range / decode count / engines / dimensions come from
# bench.config; selection lists default to "all").
# ---------------------------------------------------------------------------
COUNT="$DECODE_COUNT"
ENGINES="ours,java"
DIMENSIONS="sync,rpc,decode"
OUT_DIR="$RESULTS_DIR"

# Known shared inputs (also documented in README). Every dimension's runners
# sync / seed / serve from the same user-supplied snapshot, so it is the one
# shared input we check up-front: a missing input fails loudly here instead of
# producing bogus numbers downstream. The vanilla java-tron jar is the shared
# input the java side of every dimension needs, so it is checked too whenever
# java is selected. All paths come from bench.config (overridable by env).
SNAPSHOT_INPUT="$SNAPSHOT_PATH"
JAVA_JAR_INPUT="${JAVA_TRON_JAR:-$JT_BUILT_JAR}"

usage() {
    sed -n '2,/^set -uo pipefail/p' "$0" | sed '/^set -uo pipefail/d; s/^# \{0,1\}//'
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --from)       FROM="$2"; shift 2 ;;
        --to)         TO="$2"; shift 2 ;;
        --count)      COUNT="$2"; shift 2 ;;
        --engines)    ENGINES="$2"; shift 2 ;;
        --dimensions) DIMENSIONS="$2"; shift 2 ;;
        --out)        OUT_DIR="$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            echo "Try '$0 --help'." >&2
            exit 2
            ;;
    esac
done

# Resolve --out relative to the caller's CWD (not the repo root) when it is a
# relative path, then canonicalise.
case "$OUT_DIR" in
    /*) ;;
    *)  OUT_DIR="$PWD/$OUT_DIR" ;;
esac
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

# ---------------------------------------------------------------------------
# Validate the range
# ---------------------------------------------------------------------------
if ! [ "$FROM" -eq "$FROM" ] 2>/dev/null || ! [ "$TO" -eq "$TO" ] 2>/dev/null; then
    echo "ERROR: --from and --to must be integers (got from=$FROM to=$TO)." >&2
    exit 2
fi
if [ "$TO" -lt "$FROM" ]; then
    echo "ERROR: --to ($TO) must be >= --from ($FROM)." >&2
    exit 2
fi
BLOCK_COUNT=$(( TO - FROM + 1 ))

if ! [ "$COUNT" -gt 0 ] 2>/dev/null; then
    echo "ERROR: --count must be a positive integer (got '$COUNT')." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Validate the selected dimension list
# ---------------------------------------------------------------------------
SELECTED_DIMS=()
IFS=',' read -ra _dims <<<"$DIMENSIONS"
for d in "${_dims[@]}"; do
    d="$(printf '%s' "$d" | tr -d '[:space:]')"
    [ -n "$d" ] || continue
    case "$d" in
        sync|rpc|decode) SELECTED_DIMS+=("$d") ;;
        *)
            echo "ERROR: unknown dimension '$d' (valid: sync, rpc, decode)." >&2
            exit 2
            ;;
    esac
done
if [ "${#SELECTED_DIMS[@]}" -eq 0 ]; then
    echo "ERROR: no dimensions selected (--dimensions was '$DIMENSIONS')." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Validate the selected engine list
# ---------------------------------------------------------------------------
SELECTED=()
IFS=',' read -ra _eng <<<"$ENGINES"
for e in "${_eng[@]}"; do
    e="$(printf '%s' "$e" | tr -d '[:space:]')"
    [ -n "$e" ] || continue
    case "$e" in
        ours|java) SELECTED+=("$e") ;;
        *)
            echo "ERROR: unknown engine '$e' (valid: ours, java)." >&2
            exit 2
            ;;
    esac
done
if [ "${#SELECTED[@]}" -eq 0 ]; then
    echo "ERROR: no engines selected (--engines was '$ENGINES')." >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Per-(dimension, engine) wiring. Each dimension has its own pair of runners
# under bench/<dim>/ (sync lives directly in bench/), takes the arguments that
# dimension's runner expects, and writes a known result JSON. These three
# helpers resolve the runner path, the argument vector, and the expected output
# file for a (dimension, engine) pair -- everything else (the loop, pre-flight,
# bookkeeping) stays dimension-agnostic.
# ---------------------------------------------------------------------------

# dim_runner <dimension> <engine> -> path to that runner script
dim_runner() {
    case "$1" in
        sync)   echo "$BENCH_DIR/$2.sh" ;;
        decode) echo "$BENCH_DIR/decode/$2.sh" ;;
        rpc)    echo "$BENCH_DIR/rpc/$2.sh" ;;
    esac
}

# dim_result_file <dimension> <engine> -> result JSON the runner is expected to
# write into $OUT_DIR (used as a post-run sanity check).
dim_result_file() {
    case "$1" in
        sync)   echo "$OUT_DIR/$2.json" ;;
        decode) echo "$OUT_DIR/decode-$2.json" ;;
        rpc)    echo "$OUT_DIR/rpc-$2.json" ;;
    esac
}

# dim_run <dimension> <engine> : invoke the runner with the args it expects.
#   sync   : --from N --to N --out DIR
#   decode : --count N --out DIR     (decode is corpus-block-count driven)
#   rpc    : --out DIR               (serves the whole snapshot; no range)
dim_run() {
    local dim="$1" eng="$2" runner
    runner="$(dim_runner "$dim" "$eng")"
    case "$dim" in
        sync)   "$runner" --from "$FROM" --to "$TO" --out "$OUT_DIR" ;;
        decode) "$runner" --count "$COUNT" --out "$OUT_DIR" ;;
        rpc)    "$runner" --out "$OUT_DIR" ;;
    esac
}

# ---------------------------------------------------------------------------
# Pre-flight: the shared inputs must exist, or we refuse to run. A missing
# snapshot means any number we produce would be meaningless; the vanilla
# java-tron jar is the shared input the java side of every dimension needs.
# Fail loudly here instead of producing bogus numbers downstream. Each runner
# additionally verifies its own dimension-specific inputs.
# ---------------------------------------------------------------------------
echo "==> Pre-flight checks"
echo "    dimensions     : ${SELECTED_DIMS[*]}"
echo "    engines        : ${SELECTED[*]}"
echo "    sync range     : [$FROM, $TO]  ($BLOCK_COUNT blocks)"
echo "    decode count   : $COUNT blocks"
echo "    results dir    : $OUT_DIR"
echo "    bench work dir : $BENCH_WORK"
echo "    snapshot       : $SNAPSHOT_INPUT"
echo "    sync source    : ${SYNC_PEER:-public discovery}"
echo

fail=0
if ! bench_require_file "$SNAPSHOT_INPUT/database" "snapshot (run bootstrap.sh / set SNAPSHOT_PATH)"; then
    fail=1
fi
# The vanilla java-tron jar is needed by the java side of every dimension.
if printf '%s\n' "${SELECTED[@]}" | grep -qx java; then
    if ! bench_require_file "$JAVA_JAR_INPUT" "java-tron jar (run bench/bootstrap.sh --only java)"; then
        fail=1
    fi
fi
# Every selected (dimension, engine) runner must be present and executable.
for d in "${SELECTED_DIMS[@]}"; do
    for e in "${SELECTED[@]}"; do
        runner="$(dim_runner "$d" "$e")"
        if [ ! -e "$runner" ]; then
            echo "ERROR: missing runner for $d/$e: $runner" >&2
            fail=1
        elif [ ! -x "$runner" ]; then
            echo "ERROR: runner not executable: $runner (chmod +x it)" >&2
            fail=1
        fi
    done
done
if [ "$fail" -ne 0 ]; then
    echo >&2
    echo "Pre-flight failed; refusing to run (no bogus numbers will be written)." >&2
    exit 1
fi
echo "==> Pre-flight OK"
echo

# ---------------------------------------------------------------------------
# Run every selected (dimension, engine), in series (each pins the machine;
# running them concurrently would corrupt throughput, latency, and CPU
# measurements). The report tolerates any subset succeeding, so a single
# runner failure is a warning, not a hard stop.
# ---------------------------------------------------------------------------
export BENCH_OUT_DIR="$OUT_DIR"
declare -A RC
RUN_TOTAL=0
for d in "${SELECTED_DIMS[@]}"; do
    for e in "${SELECTED[@]}"; do
        RUN_TOTAL=$(( RUN_TOTAL + 1 ))
        runner="$(dim_runner "$d" "$e")"
        result="$(dim_result_file "$d" "$e")"
        echo "============================================================"
        echo "==> dimension: $d   engine: $e"
        echo "    runner : $runner"
        echo "============================================================"
        # The runner owns writing its result JSON; dimension specifics
        # (snapshot reset, apply/decode/serve mechanism, version stamp,
        # Block-STM toggle, JIT warmup) live inside the runner.
        if dim_run "$d" "$e"; then
            RC["$d/$e"]=0
            echo "==> $d/$e completed"
        else
            RC["$d/$e"]=$?
            echo "WARNING: $d/$e runner exited with code ${RC[$d/$e]}." >&2
            echo "         Continuing; the report includes only what succeeded." >&2
        fi
        # Sanity: confirm the runner actually produced its JSON.
        if [ ! -s "$result" ]; then
            echo "WARNING: $d/$e did not write $result." >&2
            RC["$d/$e"]=1
        fi
        echo
    done
done

# ---------------------------------------------------------------------------
# Report. report.py reads every $OUT_DIR/*.json and writes REPORT.md.
# ---------------------------------------------------------------------------
echo "============================================================"
echo "==> Generating report"
echo "============================================================"
report_py="$BENCH_DIR/report.py"
if [ ! -e "$report_py" ]; then
    echo "ERROR: missing $report_py (the report generator)." >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "ERROR: python3 not found; cannot generate the report." >&2
    exit 1
fi
# report.py reads --results <dir> and defaults its output to <results>/REPORT.md.
if ! python3 "$report_py" --results "$OUT_DIR"; then
    echo "ERROR: report.py failed." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Final summary line.
# ---------------------------------------------------------------------------
report_md="$OUT_DIR/REPORT.md"
echo
echo "============================================================"
ok=0
for d in "${SELECTED_DIMS[@]}"; do
    for e in "${SELECTED[@]}"; do
        [ "${RC[$d/$e]:-1}" -eq 0 ] && ok=$(( ok + 1 ))
    done
done
echo "==> Done. $ok/${RUN_TOTAL} runner(s) succeeded across dimensions [${SELECTED_DIMS[*]}]."
if [ -s "$report_md" ]; then
    echo "==> Report: $report_md"
else
    echo "==> Per-dimension JSON: $OUT_DIR/*.json (REPORT.md not found at $report_md)"
fi
echo "============================================================"

# Exit non-zero if any selected runner failed, so CI / callers notice.
for d in "${SELECTED_DIMS[@]}"; do
    for e in "${SELECTED[@]}"; do
        if [ "${RC[$d/$e]:-1}" -ne 0 ]; then
            exit 1
        fi
    done
done
exit 0
