#!/usr/bin/env python3
"""Render the "tron-goblin-node vs java-tron" multi-dimension benchmark report.

The benchmark suite measures three independent dimensions, each writing one JSON
file per engine into the results dir:

  * **sync**   -- block-apply throughput while peer-syncing a fixed range
                  (results/ours.json, results/java.json; these carry NO
                  `dimension` key, so a missing dimension is treated as "sync").
  * **decode** -- pure protobuf decode + per-tx parameter-decode throughput
                  (results/decode-ours.json, results/decode-java.json).
  * **rpc**    -- read-only HTTP /wallet/* query latency + throughput, plus
                  steady-state idle RAM (results/rpc-ours.json, rpc-java.json).

This script loads EVERY *.json in the results dir, groups them by
`(dimension, engine)`, and renders a single public-facing Markdown report
(REPORT.md) with a combined headline, a section per present dimension (each with
a table + a proportional ASCII bar chart), the methodology, and the caveats.

It is robust to any subset of dimensions being present: a dimension is rendered
only when its files exist, and a per-engine comparison clause is shown only when
BOTH engines reported it. Missing/garbled files are skipped with a warning; a
missing key never crashes -- it renders as "-".

Pure python3 stdlib only (json, sys, os, glob, argparse) -- no third-party deps.

Usage:
  bench/report.py [--results DIR] [--out FILE]
    --results DIR   dir of *.json metric files   (default: bench/results)
    --out FILE      output Markdown path          (default: <results>/REPORT.md)
"""

import argparse
import glob
import json
import os
import sys

# Dimensions we know about, in display order.
DIMENSIONS = ("sync", "rpc", "decode")

# Engines we know about, in the order we want them displayed.
ENGINE_ORDER = ("ours", "java")

# Friendly display names.
ENGINE_LABEL = {
    "ours": "tron-goblin-node (ours)",
    "java": "java-tron",
}

# The headline query for the per-query req/s bar chart (the VM read path -- the
# most representative "real work" query in the plan).
HEADLINE_QUERY = "triggerconstantcontract"


# ---------------------------------------------------------------------------
# Loading + grouping
# ---------------------------------------------------------------------------

def load_metrics(results_dir):
    """Load every *.json metric file, grouped as metrics[dimension][engine].

    A file with no `dimension` key is treated as the "sync" dimension (the
    block-apply runners predate the dimension key and never emit it). A file
    with no `engine` key is skipped. Garbled / unreadable files are skipped
    with a warning rather than crashing the whole report.
    """
    metrics = {}
    pattern = os.path.join(results_dir, "*.json")
    for path in sorted(glob.glob(pattern)):
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            print("warning: skipping %s: %s" % (path, exc), file=sys.stderr)
            continue
        if not isinstance(data, dict):
            print("warning: %s is not a JSON object, skipping" % path,
                  file=sys.stderr)
            continue
        engine = data.get("engine")
        if not engine:
            print("warning: %s has no 'engine' key, skipping" % path,
                  file=sys.stderr)
            continue
        dimension = data.get("dimension") or "sync"
        metrics.setdefault(dimension, {})[engine] = data
    return metrics


def ordered_engines(by_engine):
    """Engines present, known ones first (ENGINE_ORDER), then any extras."""
    known = [e for e in ENGINE_ORDER if e in by_engine]
    extra = sorted(e for e in by_engine if e not in ENGINE_ORDER)
    return known + extra


def present_dimensions(metrics):
    """Dimensions present in the data, known ones first, then any extras."""
    known = [d for d in DIMENSIONS if d in metrics]
    extra = sorted(d for d in metrics if d not in DIMENSIONS)
    return known + extra


# ---------------------------------------------------------------------------
# Number formatting helpers
# ---------------------------------------------------------------------------

def fnum(value, ndigits):
    """Coerce to float and round; return None when not numeric."""
    try:
        return round(float(value), ndigits)
    except (TypeError, ValueError):
        return None


def fmt(value, ndigits):
    """Format a number with fixed digits, or '-' when missing."""
    n = fnum(value, ndigits)
    if n is None:
        return "-"
    if ndigits == 0:
        return "%d" % int(round(n))
    return "%.*f" % (ndigits, n)


def fmt_thousands(value, ndigits):
    """Format a number with thousands separators, or '-' when missing."""
    n = fnum(value, ndigits)
    if n is None:
        return "-"
    if ndigits == 0:
        return "{:,}".format(int(round(n)))
    return "{:,.{p}f}".format(n, p=ndigits)


def ratio(num, den):
    """num/den as a float, or None when not computable."""
    n, d = fnum(num, 6), fnum(den, 6)
    if n is None or d is None or d <= 0:
        return None
    return n / d


# ---------------------------------------------------------------------------
# Generic renderers
# ---------------------------------------------------------------------------

def render_md_table(headers, rows):
    """A GitHub-flavoured Markdown table from headers + a list of row lists."""
    out = [headers, ["---"] * len(headers)]
    out.extend(rows)
    return "\n".join("| " + " | ".join(str(c) for c in r) + " |" for r in out)


def render_bar_chart(title, pairs, ndigits, unit, width=40, note=None):
    """A proportional ASCII bar chart from a list of (label, value) pairs.

    Bars are scaled to the largest value (the longest bar is `width` chars).
    `pairs` whose value is None or negative are dropped. Returns a Markdown
    section (heading + fenced block).
    """
    clean = [(lbl, fnum(v, ndigits)) for lbl, v in pairs]
    clean = [(lbl, v) for lbl, v in clean if v is not None and v >= 0]
    if not clean:
        return "### %s\n\n_(no data)_\n" % title

    label_w = max(len(lbl) for lbl, _ in clean)
    peak = max(v for _, v in clean) or 1.0

    lines = ["### %s" % title, "", "```"]
    for lbl, v in clean:
        filled = int(round((v / peak) * width)) if peak else 0
        filled = max(filled, 1 if v > 0 else 0)
        bar = "#" * filled
        val = fmt_thousands(v, ndigits)
        lines.append("%-*s | %-*s %s %s" % (label_w, lbl, width, bar, val, unit))
    lines.append("```")
    if note:
        lines.append("")
        lines.append(note)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Headline
# ---------------------------------------------------------------------------

def headline_clauses(metrics):
    """Build the bold headline clauses for whatever dimensions have both engines.

    Returns a list of clause strings (already without leading separators).
    """
    clauses = []

    # Sync: blocks/sec ours vs java.
    sync = metrics.get("sync", {})
    if "ours" in sync and "java" in sync:
        r = ratio(sync["ours"].get("blocks_per_sec"),
                  sync["java"].get("blocks_per_sec"))
        if r is not None:
            clauses.append("**%.1fx faster sync**" % r)

    # Decode: blocks/sec ours vs java (txs/sec mentioned in the section).
    dec = metrics.get("decode", {})
    if "ours" in dec and "java" in dec:
        r = ratio(dec["ours"].get("blocks_per_sec"),
                  dec["java"].get("blocks_per_sec"))
        if r is not None:
            clauses.append("**%.1fx faster decode**" % r)

    # RPC: max over query types of ours/java req/s at the highest shared
    # concurrency ("up to" N.Nx higher query throughput).
    rpc = metrics.get("rpc", {})
    if "ours" in rpc and "java" in rpc:
        best = best_query_speedup(rpc["ours"], rpc["java"])
        if best is not None:
            clauses.append("**up to %.1fx higher query throughput**" % best)

    # RAM: java/ours idle RSS (fallback peak RSS), preferring the rpc dimension
    # for the idle figure.
    ram = ram_ratio(metrics)
    if ram is not None:
        clauses.append("**%.1fx less RAM**" % ram)

    return clauses


def best_query_speedup(ours_rpc, java_rpc):
    """Max ours/java req_per_sec over query types at the highest shared concurrency."""
    best = None
    for qtype in shared_query_types(ours_rpc, java_rpc):
        c = highest_shared_concurrency(ours_rpc, java_rpc, qtype)
        if c is None:
            continue
        o = query_at(ours_rpc, qtype, c)
        j = query_at(java_rpc, qtype, c)
        if o is None or j is None:
            continue
        r = ratio(o.get("req_per_sec"), j.get("req_per_sec"))
        if r is not None and (best is None or r > best):
            best = r
    return best


def ram_ratio(metrics):
    """java/ours RAM ratio: idle RSS from rpc (preferred), else peak RSS anywhere."""
    rpc = metrics.get("rpc", {})
    if "ours" in rpc and "java" in rpc:
        r = ratio(rpc["java"].get("idle_rss_mb"), rpc["ours"].get("idle_rss_mb"))
        if r is not None:
            return r
    # Fallback: peak RSS from any dimension that has both engines.
    for dim in present_dimensions(metrics):
        by_engine = metrics[dim]
        if "ours" in by_engine and "java" in by_engine:
            r = ratio(by_engine["java"].get("peak_rss_mb"),
                      by_engine["ours"].get("peak_rss_mb"))
            if r is not None:
                return r
    return None


def render_headline(metrics):
    """The bold combined headline line (or a soft note when no comparison exists)."""
    clauses = headline_clauses(metrics)
    if not clauses:
        return ("_No head-to-head comparison yet: a headline needs at least one "
                "dimension with both `ours` and `java` results._")
    return "tron-goblin-node vs java-tron: " + " &middot; ".join(clauses)


# ---------------------------------------------------------------------------
# RPC / query helpers
# ---------------------------------------------------------------------------

def query_rows(rpc_engine):
    """The queries[] list of an rpc-dimension engine dict (possibly empty)."""
    qs = rpc_engine.get("queries")
    return qs if isinstance(qs, list) else []


def shared_query_types(ours_rpc, java_rpc):
    """Query types present for BOTH engines, in ours' first-seen order."""
    j_types = {q.get("type") for q in query_rows(java_rpc)}
    seen, ordered = set(), []
    for q in query_rows(ours_rpc):
        t = q.get("type")
        if t and t in j_types and t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def concurrencies_for(rpc_engine, qtype):
    """The set of concurrency levels reported for a query type."""
    levels = set()
    for q in query_rows(rpc_engine):
        if q.get("type") == qtype:
            c = fnum(q.get("concurrency"), 0)
            if c is not None:
                levels.add(int(c))
    return levels


def highest_shared_concurrency(ours_rpc, java_rpc, qtype):
    """Highest concurrency level both engines tested for a query type."""
    shared = concurrencies_for(ours_rpc, qtype) & concurrencies_for(java_rpc, qtype)
    return max(shared) if shared else None


def query_at(rpc_engine, qtype, concurrency):
    """The query result dict for (type, concurrency), or None."""
    for q in query_rows(rpc_engine):
        if q.get("type") == qtype and fnum(q.get("concurrency"), 0) == concurrency:
            return q
    return None


# ---------------------------------------------------------------------------
# Per-dimension sections
# ---------------------------------------------------------------------------

def section_sync(by_engine):
    engines = ordered_engines(by_engine)
    out = ["## Sync (block-apply throughput)", ""]
    out.append("Peer-syncing an identical block range from the same reference "
               "node, off the same pristine snapshot. Higher blocks/sec is "
               "better; lower RSS is better.")
    out.append("")

    headers = ["engine", "blocks", "wall_clock_s", "blocks/sec",
               "peak_rss_mb", "avg_cpu_pct"]
    rows = []
    for e in engines:
        m = by_engine[e]
        rows.append([
            ENGINE_LABEL.get(e, e),
            fmt_thousands(m.get("blocks"), 0),
            fmt(m.get("wall_clock_s"), 1),
            fmt(m.get("blocks_per_sec"), 2),
            fmt_thousands(m.get("peak_rss_mb"), 0),
            fmt(m.get("avg_cpu_pct"), 1),
        ])
    out.append(render_md_table(headers, rows))
    out.append("")

    if "ours" in by_engine and "java" in by_engine:
        r = ratio(by_engine["ours"].get("blocks_per_sec"),
                  by_engine["java"].get("blocks_per_sec"))
        if r is not None:
            out.append("**ours syncs %.1fx faster** (%s vs %s blocks/sec)."
                       % (r,
                          fmt(by_engine["ours"].get("blocks_per_sec"), 2),
                          fmt(by_engine["java"].get("blocks_per_sec"), 2)))
            out.append("")

    pairs = [(ENGINE_LABEL.get(e, e), by_engine[e].get("blocks_per_sec"))
             for e in engines]
    out.append(render_bar_chart("Sync throughput (blocks/sec, higher is better)",
                                pairs, 2, "blk/s"))
    return "\n".join(out)


def section_decode(by_engine):
    engines = ordered_engines(by_engine)
    out = ["## Decode (parse + parameter-decode throughput)", ""]
    out.append("Decoding an identical in-memory block corpus: parse each Block "
               "protobuf, iterate its transactions, and decode each contract "
               "call's parameters. Pure CPU -- no state, no I/O in the timed "
               "loop. Higher is better.")
    out.append("")

    headers = ["engine", "blocks", "txs", "blocks/sec", "txs/sec", "peak_rss_mb"]
    rows = []
    for e in engines:
        m = by_engine[e]
        rows.append([
            ENGINE_LABEL.get(e, e),
            fmt_thousands(m.get("blocks"), 0),
            fmt_thousands(m.get("txs"), 0),
            fmt_thousands(m.get("blocks_per_sec"), 0),
            fmt_thousands(m.get("txs_per_sec"), 0),
            fmt_thousands(m.get("peak_rss_mb"), 0),
        ])
    out.append(render_md_table(headers, rows))
    out.append("")

    if "ours" in by_engine and "java" in by_engine:
        rb = ratio(by_engine["ours"].get("blocks_per_sec"),
                   by_engine["java"].get("blocks_per_sec"))
        rt = ratio(by_engine["ours"].get("txs_per_sec"),
                   by_engine["java"].get("txs_per_sec"))
        bits = []
        if rb is not None:
            bits.append("%.1fx the blocks/sec" % rb)
        if rt is not None:
            bits.append("%.1fx the txs/sec (%s vs %s tx/s)"
                        % (rt,
                           fmt_thousands(by_engine["ours"].get("txs_per_sec"), 0),
                           fmt_thousands(by_engine["java"].get("txs_per_sec"), 0)))
        if bits:
            out.append("**ours decodes " + " and ".join(bits) + ".**")
            out.append("")

    bpairs = [(ENGINE_LABEL.get(e, e), by_engine[e].get("blocks_per_sec"))
              for e in engines]
    out.append(render_bar_chart("Decode throughput (blocks/sec, higher is better)",
                                bpairs, 0, "blk/s"))
    tpairs = [(ENGINE_LABEL.get(e, e), by_engine[e].get("txs_per_sec"))
              for e in engines]
    out.append(render_bar_chart("Decode throughput (txs/sec, higher is better)",
                                tpairs, 0, "tx/s"))
    return "\n".join(out)


def section_rpc(by_engine):
    out = ["## Query / RPC (read-only /wallet/* performance)", ""]
    out.append("Both engines serve the same read-only mainnet snapshot over the "
               "same HTTP `/wallet/*` API, hit by the same query plan in "
               "isolated runs. The table compares each query at the highest "
               "concurrency both engines exercised. Higher req/s and lower p99 "
               "are better.")
    out.append("")

    have_both = "ours" in by_engine and "java" in by_engine
    if have_both:
        ours_rpc, java_rpc = by_engine["ours"], by_engine["java"]
        headers = ["query", "concurrency", "ours req/s", "java req/s",
                   "speedup", "ours p99 ms", "java p99 ms"]
        rows = []
        any_error = False
        for qtype in shared_query_types(ours_rpc, java_rpc):
            c = highest_shared_concurrency(ours_rpc, java_rpc, qtype)
            if c is None:
                continue
            o = query_at(ours_rpc, qtype, c)
            j = query_at(java_rpc, qtype, c)
            if o is None or j is None:
                continue
            r = ratio(o.get("req_per_sec"), j.get("req_per_sec"))
            speedup = "%.1fx" % r if r is not None else "-"
            rows.append([
                qtype,
                "%d" % c,
                fmt_thousands(o.get("req_per_sec"), 0),
                fmt_thousands(j.get("req_per_sec"), 0),
                speedup,
                fmt(o.get("p99_ms"), 2),
                fmt(j.get("p99_ms"), 2),
            ])
            for q in (o, j):
                er = fnum(q.get("error_rate"), 6)
                if er is not None and er > 0:
                    any_error = True
        if rows:
            out.append(render_md_table(headers, rows))
            out.append("")
        else:
            out.append("_No query types are shared between both engines._")
            out.append("")
        if any_error:
            out.append("_Note: at least one query reported a non-zero error "
                       "rate; see the per-engine `queries[]` in the result "
                       "JSON for the exact counts._")
            out.append("")

        # Headline req/s bar chart for the VM read query (fallback: any shared).
        bar_type = HEADLINE_QUERY
        shared = shared_query_types(ours_rpc, java_rpc)
        if bar_type not in shared and shared:
            bar_type = shared[0]
        c = highest_shared_concurrency(ours_rpc, java_rpc, bar_type) if shared else None
        if c is not None:
            o = query_at(ours_rpc, bar_type, c)
            j = query_at(java_rpc, bar_type, c)
            pairs = []
            if o is not None:
                pairs.append((ENGINE_LABEL.get("ours"), o.get("req_per_sec")))
            if j is not None:
                pairs.append((ENGINE_LABEL.get("java"), j.get("req_per_sec")))
            out.append(render_bar_chart(
                "Query throughput: `%s` at concurrency %d (req/s, higher is better)"
                % (bar_type, c),
                pairs, 0, "req/s"))
    else:
        # Only one engine present -- render its own queries at the top concurrency.
        for e in ordered_engines(by_engine):
            rpc = by_engine[e]
            headers = ["query", "concurrency", "req/s", "p50 ms", "p99 ms",
                       "error_rate"]
            rows = []
            for q in query_rows(rpc):
                rows.append([
                    q.get("type", "?"),
                    fmt(q.get("concurrency"), 0),
                    fmt_thousands(q.get("req_per_sec"), 0),
                    fmt(q.get("p50_ms"), 2),
                    fmt(q.get("p99_ms"), 2),
                    fmt(q.get("error_rate"), 4),
                ])
            out.append("### %s" % ENGINE_LABEL.get(e, e))
            out.append("")
            if rows:
                out.append(render_md_table(headers, rows))
            else:
                out.append("_(no query data)_")
            out.append("")

    return "\n".join(out)


def section_memory(metrics):
    """Memory / RAM section: idle RSS (from rpc) + peak RSS (from any dimension)."""
    rpc = metrics.get("rpc", {})

    # Collect idle RSS (rpc only) and peak RSS (best/any dimension) per engine.
    engines = []
    for dim in present_dimensions(metrics):
        for e in ordered_engines(metrics[dim]):
            if e not in engines:
                engines.append(e)
    # Keep the canonical order.
    engines = ordered_engines({e: True for e in engines})

    idle = {}
    peak = {}
    for e in engines:
        if e in rpc:
            v = fnum(rpc[e].get("idle_rss_mb"), 1)
            if v is not None:
                idle[e] = v
        # Peak: prefer rpc, then sync, then decode (any with a value).
        for dim in ("rpc", "sync", "decode"):
            be = metrics.get(dim, {})
            if e in be:
                v = fnum(be[e].get("peak_rss_mb"), 1)
                if v is not None:
                    peak[e] = v
                    break

    if not idle and not peak:
        return ""

    out = ["## Memory / RAM", ""]
    out.append("`idle_rss_mb` is the resident footprint serving the snapshot at "
               "rest with no load (from the query/RPC dimension); `peak_rss_mb` "
               "is the highest resident memory observed under load. Lower is "
               "better -- the native process allocates on demand, while the JVM "
               "pre-touches a large fixed heap.")
    out.append("")

    headers = ["engine", "idle_rss_mb", "peak_rss_mb"]
    rows = []
    for e in engines:
        rows.append([
            ENGINE_LABEL.get(e, e),
            fmt_thousands(idle.get(e), 0),
            fmt_thousands(peak.get(e), 0),
        ])
    out.append(render_md_table(headers, rows))
    out.append("")

    if "ours" in idle and "java" in idle:
        r = ratio(idle["java"], idle["ours"])
        if r is not None:
            out.append("**ours uses %.1fx less idle RAM** (%s MB vs %s MB)."
                       % (r, fmt_thousands(idle["ours"], 0),
                          fmt_thousands(idle["java"], 0)))
            out.append("")

    # Idle-RSS bar chart (lower is better -- our big win).
    if idle:
        pairs = [(ENGINE_LABEL.get(e, e), idle[e]) for e in engines if e in idle]
        out.append(render_bar_chart("Idle RSS (MB, lower is better)",
                                    pairs, 0, "MB"))
    elif peak:
        pairs = [(ENGINE_LABEL.get(e, e), peak[e]) for e in engines if e in peak]
        out.append(render_bar_chart("Peak RSS (MB, lower is better)",
                                    pairs, 0, "MB"))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Methodology + caveats (static, public-facing)
# ---------------------------------------------------------------------------

METHODOLOGY = """\
## Methodology

Every comparison is `tron-goblin-node` ("ours") against a stock, vanilla
java-tron v4.8.1.1 FullNode ("java"), on the same machine, run separately.

* **Sync** -- a symmetric peer-sync. Both engines fetch and apply the **same
  fixed block range** from the **same reference node** over p2p, each starting
  from the **same pristine snapshot**. The network path is identical for both
  and cancels out of the comparison; the timed window is the apply of the range
  only, with the one-time snapshot load reported separately as
  `snapshot_load_s`. `blocks_per_sec = blocks / wall_clock_s`. Block-STM
  (`vm.parallel_exec`) is on for ours.

* **Decode** -- an identical in-memory corpus, decode-only. Both engines load
  the same length-prefixed block corpus into memory (untimed), then in a tight
  loop parse each `Block` protobuf, iterate its transactions, and decode each
  contract's parameters (the production `decode_tx_summary` scope: typed
  parameter unpack + 4-byte selector -> method name + USDT ABI amount). No
  state, no RocksDB, no execution. The java side runs JIT-warmup passes that are
  not counted before the measured passes, so HotSpot is warm. See
  [`bench/decode/README.md`](decode/README.md) for the exact decode contract.

* **Query / RPC** -- an identical HTTP `/wallet/*` query workload. Both engines
  serve the **same read-only snapshot** with sync/p2p off, hit by the **same
  query plan** (same bodies, same concurrency sweep, same duration) through the
  same load generator, in **isolated** runs (never concurrently) so latencies
  are not cross-contaminated. We also sample steady-state **idle** RSS (no load)
  and peak RSS under load. See [`bench/rpc/README.md`](rpc/README.md) for the
  query plan and fairness model.
"""

CAVEATS = """\
## Caveats

* **JVM heap inflates java RSS.** java-tron runs a large fixed, pre-touched heap
  (`-Xms=-Xmx`), so its RSS reflects the configured heap, not the working set.
  The native process allocates on demand. The RAM ratio is therefore
  **conservative / indicative**, reported as-measured for honesty -- not a claim
  about the minimum memory either engine could survive on.
* **Single-run, warm-cache numbers.** Each figure is one run with a warm page
  cache; expect run-to-run variance from GC, scheduler noise, and cache warmth.
  Re-run for a distribution.
* **Block-STM is on for ours** (`vm.parallel_exec`) in the sync dimension -- the
  parallel block-execution path this benchmark exists to show.
* **java is stock vanilla v4.8.1.1**, un-instrumented, on the same machine.
* CPU percentages are whole-machine relative (>100% means multiple cores busy).
"""


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def render_provenance(metrics):
    """A short per-(dimension, engine) provenance list for traceability."""
    lines = []
    for dim in present_dimensions(metrics):
        by_engine = metrics[dim]
        for e in ordered_engines(by_engine):
            m = by_engine[e]
            ver = m.get("version", "?")
            if dim == "sync":
                lines.append(
                    "- **%s / %s** (`%s`): blocks %s..%s"
                    % (dim, ENGINE_LABEL.get(e, e), ver,
                       m.get("block_from", "?"), m.get("block_to", "?")))
            elif dim == "decode":
                lines.append(
                    "- **%s / %s** (`%s`): %s blocks, %s txs"
                    % (dim, ENGINE_LABEL.get(e, e), ver,
                       fmt_thousands(m.get("blocks"), 0),
                       fmt_thousands(m.get("txs"), 0)))
            else:  # rpc / unknown
                lines.append("- **%s / %s** (`%s`)"
                             % (dim, ENGINE_LABEL.get(e, e), ver))
    return "\n".join(lines)


def render_notes(metrics):
    """Per-(dimension, engine) honesty notes footer."""
    lines = []
    for dim in present_dimensions(metrics):
        by_engine = metrics[dim]
        for e in ordered_engines(by_engine):
            note = by_engine[e].get("notes")
            if note:
                lines.append("- **%s / %s:** %s"
                             % (dim, ENGINE_LABEL.get(e, e),
                                " ".join(str(note).split())))
    return lines


def build_report(metrics):
    dims = present_dimensions(metrics)
    if not dims:
        return ("# tron-goblin-node vs java-tron -- benchmark\n\n"
                "_No metric JSON files found in the results dir._\n")

    out = []
    out.append("# tron-goblin-node vs java-tron")
    out.append("")
    out.append(render_headline(metrics))
    out.append("")
    out.append("A native Rust TRON full node, measured head-to-head against a "
               "stock java-tron FullNode across three independent dimensions: "
               "block-sync throughput, decode throughput, and read-only query "
               "serving (plus memory footprint).")
    out.append("")
    out.append("**Dimensions in this report:** " + ", ".join(dims) + ".")
    out.append("")

    # Sections, in canonical order, only for present dimensions.
    if "sync" in metrics:
        out.append(section_sync(metrics["sync"]))
        out.append("")
    if "rpc" in metrics:
        out.append(section_rpc(metrics["rpc"]))
        out.append("")
    if "decode" in metrics:
        out.append(section_decode(metrics["decode"]))
        out.append("")

    mem = section_memory(metrics)
    if mem:
        out.append(mem)
        out.append("")

    # Any unknown/extra dimensions: render a minimal raw table so nothing is lost.
    for dim in dims:
        if dim in ("sync", "rpc", "decode"):
            continue
        by_engine = metrics[dim]
        out.append("## %s" % dim)
        out.append("")
        out.append("_Unrecognised dimension; raw values shown._")
        out.append("")
        for e in ordered_engines(by_engine):
            out.append("- **%s**: `%s`"
                       % (ENGINE_LABEL.get(e, e), json.dumps(by_engine[e])))
        out.append("")

    out.append(METHODOLOGY)
    out.append("")
    out.append(CAVEATS)
    out.append("")

    out.append("## Provenance")
    out.append("")
    out.append(render_provenance(metrics))
    out.append("")

    notes = render_notes(metrics)
    if notes:
        out.append("## Notes")
        out.append("")
        out.extend(notes)
        out.append("")

    return "\n".join(out)


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(
        description="Render the tron-goblin-node vs java-tron benchmark report.")
    parser.add_argument("--results", default=os.path.join(here, "results"),
                        help="dir of *.json metric files (default: bench/results)")
    parser.add_argument("--out", default=None,
                        help="output Markdown path (default: <results>/REPORT.md)")
    args = parser.parse_args(argv)

    results_dir = args.results
    out_path = args.out or os.path.join(results_dir, "REPORT.md")

    metrics = load_metrics(results_dir)
    report = build_report(metrics)

    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w") as fh:
        fh.write(report)
        if not report.endswith("\n"):
            fh.write("\n")

    dims = present_dimensions(metrics)
    summary = ", ".join(
        "%s[%s]" % (d, "+".join(ordered_engines(metrics[d]))) for d in dims
    ) or "none"
    print("wrote %s (dimensions: %s)" % (out_path, summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
