#!/usr/bin/env python3
"""emit_rpc_json.py -- write one engine's RPC-dimension result JSON.

The shared lib.sh `bench_emit_json` writer is hard-wired to the block-apply
schema (block_from/to, blocks_per_sec, ...). The RPC / query dimension has a
different shape, so its two runners (ours.sh, java.sh) emit through this tiny
helper instead. It is intentionally schema-specific and shared by BOTH runners
so the JSON both engines produce is identical in structure -- the report
generator can render them side by side.

Schema written to <out>:
    {
      "dimension": "rpc",
      "engine": "ours" | "java",
      "version": "<git sha | jar version>",
      "idle_rss_mb": <float>,        # steady-state idle RSS (no load)
      "peak_rss_mb": <float>,        # peak RSS under load
      "avg_cpu_pct": <float>,        # mean %CPU under load (may exceed 100)
      "queries": [ {type, concurrency, p50_ms, p99_ms, req_per_sec,
                    error_rate}, ... ],
      "notes": "<freeform>"
    }

The `queries` array is lifted verbatim from the loadgen output (the extra
count/errors/duration_s fields it carries are kept -- they are harmless detail
the report can ignore).

Usage:
    emit_rpc_json.py --out PATH --engine ENGINE --version VER \
        --idle-rss-mb F --peak-rss-mb F --avg-cpu-pct F \
        --queries-json LOADGEN_OUT.json --notes "..."
"""

import argparse
import json
import sys


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--engine", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--idle-rss-mb", type=float, required=True)
    p.add_argument("--peak-rss-mb", type=float, required=True)
    p.add_argument("--avg-cpu-pct", type=float, required=True)
    p.add_argument("--queries-json", required=True,
                   help="loadgen output JSON to lift the queries array from")
    p.add_argument("--notes", default="")
    return p.parse_args()


def main():
    a = parse_args()
    try:
        lg = json.load(open(a.queries_json))
    except (OSError, json.JSONDecodeError) as e:
        sys.stderr.write(f"emit_rpc_json.py: cannot read queries JSON: {e}\n")
        sys.exit(1)

    obj = {
        "dimension": "rpc",
        "engine": a.engine,
        "version": a.version,
        "idle_rss_mb": round(a.idle_rss_mb, 1),
        "peak_rss_mb": round(a.peak_rss_mb, 1),
        "avg_cpu_pct": round(a.avg_cpu_pct, 1),
        "queries": lg.get("queries", []),
        "notes": a.notes,
    }
    with open(a.out, "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")
    sys.stderr.write(f"emit_rpc_json.py: wrote {a.out}\n")


if __name__ == "__main__":
    main()
