# bench/lib.sh -- shared shell helpers for the tron-goblin-node benchmark suite.
#
# Sourced by the engine runners (ours.sh / java.sh) and the orchestrator
# (run.sh). Provides:
#
#   - timing helpers (bench_now_ns / bench_elapsed_s)
#   - a background resource sampler (bench_sample_proc) that records peak RSS
#     and mean CPU% of a process while it runs
#   - the canonical results-JSON writer (bench_emit_json) that all engines use
#
# Every runner writes bench/results/<engine>.json with EXACTLY this schema:
#
#   {
#     "engine": "ours" | "java",
#     "version": "<git short sha or jar version>",
#     "block_from": <int>, "block_to": <int>, "blocks": <int>,
#     "snapshot_load_s": <float>,   // open/load the pristine DB before applying
#     "wall_clock_s": <float>,      // wall-clock to apply the block range
#     "blocks_per_sec": <float>,    // blocks / wall_clock_s
#     "peak_rss_mb": <float>,       // peak resident memory of the engine process
#     "avg_cpu_pct": <float>,       // mean %CPU over the run (may exceed 100)
#     "notes": "<freeform>"
#   }
#
# bench/report.py reads every bench/results/*.json and emits REPORT.md.
#
# Helpers are written for bash under `set -uo pipefail`; they avoid `set -e`
# fragility by checking return codes explicitly where it matters.

# --------------------------------------------------------------------------
# Timing
# --------------------------------------------------------------------------

# Monotonic-enough wall clock in nanoseconds (date is not strictly monotonic
# but is fine at the second+ granularity these benchmarks operate at).
bench_now_ns() {
    date +%s%N
}

# Wall-clock seconds as a float (used as the t0/t1 markers around a phase).
bench_now_s() {
    date +%s.%N
}

# bench_elapsed_s <start_s> <end_s> -> float seconds, printed to stdout.
bench_elapsed_s() {
    awk -v a="$1" -v b="$2" 'BEGIN { printf "%.3f", (b - a) }'
}

# --------------------------------------------------------------------------
# Resource sampling
# --------------------------------------------------------------------------
#
# bench_sample_proc <pid> <out_file>
#
#   Launches a sampler loop in the BACKGROUND that, roughly once per second
#   while <pid> is alive, appends one CSV row to <out_file>:
#
#       wall_ns,vmrss_kb,vmhwm_kb,cpu_jiffies
#
#   where cpu_jiffies = utime + stime from /proc/<pid>/stat (in CLK_TCK
#   ticks). The caller is responsible for stopping the sampler when the run
#   ends (kill the returned PID) and then calling bench_sampler_summary to
#   reduce the CSV to peak_rss_mb and avg_cpu_pct.
#
#   Prints the sampler's PID on stdout. Returns non-zero if <pid> is not a
#   live process at launch time.
#
#   RSS note: this samples the MAIN pid only. For the JVM (java.sh) that is
#   the whole heap-backed process, which is what we want -- VmRSS already
#   includes the resident portion of the Java heap (-Xms/-Xmx preallocated +
#   pretouched). For our node the worker threads share the same address space,
#   so the main-pid RSS is the process total too. Document the -Xmx caveat in
#   the engine notes / README.

BENCH_CLK_TCK="$(getconf CLK_TCK 2>/dev/null || echo 100)"

bench_sample_proc() {
    local pid="$1"
    local out="$2"

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "bench_sample_proc: pid $pid is not alive" >&2
        return 1
    fi

    : > "$out" || return 1

    (
        # Sampler subshell. Exits when the target pid dies.
        while kill -0 "$pid" 2>/dev/null; do
            local stat rest vmrss vmhwm now_ns
            local -a fields
            now_ns="$(date +%s%N)"

            # CPU: utime + stime are fields 14 and 15 of /proc/<pid>/stat, but
            # the `comm` field (field 2) is parenthesised and may contain
            # spaces -- strip up to the final ") " before splitting.
            if stat="$(cat /proc/"$pid"/stat 2>/dev/null)"; then
                rest="${stat##*) }"
                read -ra fields <<<"$rest"
                # After ") ": state ppid pgrp session tty_nr tpgid flags
                # minflt cminflt majflt cmajflt utime stime ...
                #   index:   0     1    2    3       4      5    6
                #            7      8       9      10      11    12
                local utime="${fields[11]:-0}"
                local stime="${fields[12]:-0}"
                local cpu_jiffies=$(( utime + stime ))

                # RSS: VmRSS is current resident; VmHWM is the high-water mark.
                # Track both so the summary can take the true peak even if a
                # sample happens to miss the moment of maximum residency.
                vmrss="$(awk '/^VmRSS:/ { print $2; exit }' /proc/"$pid"/status 2>/dev/null)"
                vmhwm="$(awk '/^VmHWM:/ { print $2; exit }' /proc/"$pid"/status 2>/dev/null)"
                printf '%s,%s,%s,%s\n' \
                    "$now_ns" "${vmrss:-0}" "${vmhwm:-0}" "$cpu_jiffies" >> "$out"
            fi
            sleep 1
        done
    ) &

    echo "$!"
}

# bench_sampler_summary <csv_file>  ->  prints "peak_rss_mb avg_cpu_pct"
#
#   Reduces the sampler CSV to:
#     peak_rss_mb  = max(VmHWM, max VmRSS) / 1024
#     avg_cpu_pct  = (last cpu_jiffies - first cpu_jiffies) / CLK_TCK
#                    / (last_wall - first_wall) * 100
#
#   avg_cpu_pct is computed from the FIRST and LAST samples only (a clean
#   total-CPU-over-total-wall mean); it can exceed 100 on multi-core runs.
#   Prints "0 0" if there are fewer than two usable samples.
bench_sampler_summary() {
    local csv="$1"
    if [ ! -s "$csv" ]; then
        echo "0 0"
        return 0
    fi
    awk -F, -v tck="$BENCH_CLK_TCK" '
        {
            ns = $1 + 0; rss = $2 + 0; hwm = $3 + 0; jif = $4 + 0
            if (n == 0) { first_ns = ns; first_jif = jif }
            last_ns = ns; last_jif = jif
            if (rss > rss_peak) rss_peak = rss
            if (hwm > rss_peak) rss_peak = hwm
            n++
        }
        END {
            peak_mb = rss_peak / 1024.0
            cpu = 0.0
            if (n >= 2) {
                dt = (last_ns - first_ns) / 1e9
                if (dt > 0) {
                    cpu = (last_jif - first_jif) / tck / dt * 100.0
                }
            }
            printf "%.1f %.1f", peak_mb, cpu
        }
    ' "$csv"
}

# bench_stop_sampler <sampler_pid>
#
#   Stops a sampler launched by bench_sample_proc. Safe to call on an already
#   dead pid.
bench_stop_sampler() {
    local sp="$1"
    [ -n "$sp" ] || return 0
    if kill -0 "$sp" 2>/dev/null; then
        kill "$sp" 2>/dev/null || true
        wait "$sp" 2>/dev/null || true
    fi
}

# --------------------------------------------------------------------------
# Results JSON
# --------------------------------------------------------------------------
#
# bench_emit_json <engine> <version> <from> <to> \
#                 <snapshot_load_s> <wall_s> <peak_rss_mb> <avg_cpu_pct> \
#                 "<notes>"
#
#   Writes "<BENCH_OUT_DIR>/<engine>.json" (BENCH_OUT_DIR defaults to
#   bench/results, but runners SHOULD export it from their --out argument).
#   blocks and blocks_per_sec are derived here so every engine computes them
#   identically:
#
#       blocks         = to - from + 1
#       blocks_per_sec = blocks / wall_s        (0 if wall_s <= 0)
#
#   The blocks count is INCLUSIVE of both endpoints: both engines sync up to and
#   including block TO, starting from a snapshot at head FROM-1, so exactly
#   (TO - FROM + 1) blocks are applied.
bench_emit_json() {
    local engine="$1"
    local version="$2"
    local from="$3"
    local to="$4"
    local snapshot_load_s="$5"
    local wall_s="$6"
    local peak_rss_mb="$7"
    local avg_cpu_pct="$8"
    local notes="${9:-}"

    local out_dir="${BENCH_OUT_DIR:-bench/results}"
    mkdir -p "$out_dir"
    local out="$out_dir/$engine.json"

    # JSON-escape the freeform notes string (backslash, double-quote, control
    # chars). Everything else in the schema is numeric or a known-safe token.
    local notes_esc
    notes_esc="$(
        printf '%s' "$notes" | awk '
            BEGIN { ORS = "" }
            {
                if (NR > 1) printf "\\n"
                s = $0
                gsub(/\\/, "\\\\", s)
                gsub(/"/,  "\\\"", s)
                gsub(/\t/, "\\t", s)
                gsub(/\r/, "", s)
                printf "%s", s
            }
        '
    )"

    awk -v engine="$engine" -v version="$version" \
        -v from="$from" -v to="$to" \
        -v snap="$snapshot_load_s" -v wall="$wall_s" \
        -v rss="$peak_rss_mb" -v cpu="$avg_cpu_pct" \
        -v notes="$notes_esc" '
        BEGIN {
            blocks = (to + 0) - (from + 0) + 1
            bps = (wall + 0 > 0) ? blocks / (wall + 0) : 0
            printf "{\n"
            printf "  \"engine\": \"%s\",\n", engine
            printf "  \"version\": \"%s\",\n", version
            printf "  \"block_from\": %d,\n", from + 0
            printf "  \"block_to\": %d,\n", to + 0
            printf "  \"blocks\": %d,\n", blocks
            printf "  \"snapshot_load_s\": %.3f,\n", snap + 0
            printf "  \"wall_clock_s\": %.3f,\n", wall + 0
            printf "  \"blocks_per_sec\": %.3f,\n", bps
            printf "  \"peak_rss_mb\": %.1f,\n", rss + 0
            printf "  \"avg_cpu_pct\": %.1f,\n", cpu + 0
            printf "  \"notes\": \"%s\"\n", notes
            printf "}\n"
        }
    ' > "$out"

    echo "$out"
}

# --------------------------------------------------------------------------
# Misc
# --------------------------------------------------------------------------

# bench_require_file <path> <human description>
#   Fail loudly (exit 1) if a required input file/dir is missing.
bench_require_file() {
    local path="$1"
    local what="${2:-file}"
    if [ ! -e "$path" ]; then
        echo "ERROR: missing $what: $path" >&2
        return 1
    fi
    return 0
}

# --------------------------------------------------------------------------
# Portable toolchain + snapshot helpers (used by bootstrap.sh and the runners)
# --------------------------------------------------------------------------

# bench_java_bin [JDK8_HOME] -> prints the `java` to use, or empty.
#   Resolves the java executable from $1/bin/java when $1 is set, else falls
#   back to `java` on PATH. Prints nothing (and returns 1) if neither exists.
bench_java_bin() {
    local home="${1:-}"
    if [ -n "$home" ] && [ -x "$home/bin/java" ]; then
        echo "$home/bin/java"
        return 0
    fi
    if command -v java >/dev/null 2>&1; then
        command -v java
        return 0
    fi
    return 1
}

# bench_javac_bin [JDK8_HOME] -> prints the `javac` to use, or empty.
bench_javac_bin() {
    local home="${1:-}"
    if [ -n "$home" ] && [ -x "$home/bin/javac" ]; then
        echo "$home/bin/javac"
        return 0
    fi
    if command -v javac >/dev/null 2>&1; then
        command -v javac
        return 0
    fi
    return 1
}

# bench_java_is_8 <java_bin> -> 0 if the runtime reports a 1.8 version.
#   java-tron GreatVoyage requires JDK 8; runners warn (not fail) on a mismatch
#   so a deliberately-different JDK can still be tried.
bench_java_is_8() {
    local jb="$1"
    [ -n "$jb" ] || return 1
    "$jb" -version 2>&1 | grep -qE 'version "(1\.8|8)[."]'
}

# bench_copy_snapshot <snapshot_path> <dest_data_dir>
#
#   COPY-seed a writable engine data-dir from a read-only snapshot. The source
#   snapshot's RocksDB stores live at <snapshot_path>/database/<store>; both our
#   node and java-tron open their stores at <data_dir>/database/<store>, so the
#   copy plants them 1:1.
#
#   This is a PLAIN recursive copy -- never a hard-link or reset of the source.
#   The source is opened read-only and is never modified; the destination is a
#   fresh, fully owned, writable duplicate. (`cp -a` preserves the nested
#   per-store tree, including each store's metadata.) Any stale destination is
#   removed first.
#
#   Returns non-zero on failure or if the destination ends up empty.
bench_copy_snapshot() {
    local src="$1"
    local dst="$2"
    local src_db="$src/database"
    local dst_db="$dst/database"

    if [ ! -d "$src_db" ]; then
        echo "bench_copy_snapshot: source snapshot has no database/ at $src_db" >&2
        return 1
    fi
    rm -rf "$dst"
    mkdir -p "$dst_db" || return 1
    # Copy the contents of the snapshot's database/ into the dest database/.
    if command -v rsync >/dev/null 2>&1; then
        rsync -a "$src_db/" "$dst_db/" || return 1
    else
        cp -a "$src_db/." "$dst_db/" || return 1
    fi
    if [ -z "$(ls -A "$dst_db" 2>/dev/null)" ]; then
        echo "bench_copy_snapshot: destination $dst_db is empty after copy" >&2
        return 1
    fi
    return 0
}
