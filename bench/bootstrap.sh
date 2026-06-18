#!/usr/bin/env bash
#
# bench/bootstrap.sh -- one-shot, idempotent prerequisite setup for the
# tron-goblin-node vs java-tron benchmark suite, from a FRESH CLONE on ANY
# machine.
#
# It prepares everything the runners need INTO BENCH_WORK (the isolated working
# dir the suite owns; see bench.config) and touches nothing else:
#
#   (a) builds our node (`cargo build --release -p tron-node`);
#   (b) provides a vanilla java-tron FullNode jar -- uses JAVA_TRON_JAR if set,
#       otherwise clones java-tron at JAVA_TRON_TAG into BENCH_WORK and runs
#       `:framework:buildFullNodeJar`;
#   (c) verifies / locates the snapshot -- if SNAPSHOT_PATH is a valid snapshot
#       it is used as-is (READ-ONLY); else if SNAPSHOT_URL is set it is
#       downloaded + extracted into BENCH_WORK; else it fails loudly with
#       instructions;
#   (d) optionally fetches the decode-dimension block corpus into BENCH_WORK
#       (skipped if BLOCKS_FILE already exists, or if no fetch tool is present
#       -- the decode dimension is optional and prints instructions instead).
#
# Every external input is read from bench.config (overridable by environment).
# Re-running is safe: each step skips work already done.
#
# This script SCRIPTS the heavy steps; running it downloads/builds large
# artifacts (a multi-GiB snapshot, a gradle build, the corpus). Run it once on
# a machine with disk + build deps before `bench/run.sh`.

set -uo pipefail

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
export BENCH_DIR
REPO_ROOT="$(cd "${BENCH_DIR}/.." && pwd)"
export REPO_ROOT

# shellcheck source=bench/lib.sh
source "${BENCH_DIR}/lib.sh"
# shellcheck source=bench/bench.config
source "${BENCH_DIR}/bench.config"

# Which steps to run (default: all). Override with --only node|java|snapshot|corpus.
ONLY=""

usage() {
    cat <<EOF
usage: bench/bootstrap.sh [--only node|java|snapshot|corpus]

Prepares benchmark prerequisites into BENCH_WORK (${BENCH_WORK}):
  node      cargo build --release -p tron-node
  java      build/locate a vanilla java-tron FullNode jar
  snapshot  verify SNAPSHOT_PATH (or download SNAPSHOT_URL)
  corpus    fetch the decode-dimension block corpus (optional)

With no --only, runs all four steps. Idempotent.

Key config (see bench/bench.config; all overridable by environment):
  BENCH_WORK=${BENCH_WORK}
  JAVA_TRON_TAG=${JAVA_TRON_TAG}
  JAVA_TRON_JAR=${JAVA_TRON_JAR:-<unset: will build>}
  SNAPSHOT_PATH=${SNAPSHOT_PATH}
  SNAPSHOT_URL=${SNAPSHOT_URL:-<unset>}
  BLOCKS_FILE=${BLOCKS_FILE}
  FROM=${FROM}  TO=${TO}
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --only) ONLY="${2:?--only needs a step}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "bootstrap.sh: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

want() { [ -z "$ONLY" ] || [ "$ONLY" = "$1" ]; }

mkdir -p "${BENCH_WORK}"

# ===========================================================================
# (a) Build our node (release).
# ===========================================================================
if want node; then
    echo "==> [node] building tron-goblin-node (release)…"
    if [ -x "${TRON_NODE}" ] && [ -z "${ONLY}" ]; then
        echo "    ${TRON_NODE} already built; rebuilding to pick up changes…"
    fi
    if ! ( cd "${REPO_ROOT}" && cargo build --release -p tron-node ); then
        echo "ERROR: cargo build failed. Install a Rust toolchain (rustup) first." >&2
        exit 1
    fi
    if [ ! -x "${TRON_NODE}" ]; then
        echo "ERROR: build succeeded but ${TRON_NODE} is missing/not executable." >&2
        exit 1
    fi
    echo "    ok: ${TRON_NODE}"
fi

# ===========================================================================
# (b) Provide a vanilla java-tron FullNode jar.
# ===========================================================================
if want java; then
    echo "==> [java] preparing a vanilla java-tron FullNode jar…"
    if [ -n "${JAVA_TRON_JAR}" ]; then
        if [ ! -f "${JAVA_TRON_JAR}" ]; then
            echo "ERROR: JAVA_TRON_JAR is set but not found: ${JAVA_TRON_JAR}" >&2
            exit 1
        fi
        echo "    using prebuilt jar from JAVA_TRON_JAR: ${JAVA_TRON_JAR}"
    elif [ -f "${JT_BUILT_JAR}" ]; then
        echo "    already built: ${JT_BUILT_JAR} (delete it to force a rebuild)"
    else
        # Resolve a JDK 8. java-tron GreatVoyage builds + runs under JDK 8.
        javac_bin="$(bench_javac_bin "${JDK8_HOME}")" || {
            echo "ERROR: no javac found. Install JDK 8 and set JDK8_HOME or JAVA_HOME," >&2
            echo "       or set JAVA_TRON_JAR to a prebuilt vanilla FullNode jar." >&2
            exit 1
        }
        java_bin="$(bench_java_bin "${JDK8_HOME}")"
        if ! bench_java_is_8 "${java_bin}"; then
            echo "    WARNING: ${java_bin} is not JDK 8; java-tron ${JAVA_TRON_TAG} expects JDK 8." >&2
            echo "             set JDK8_HOME to a JDK 8 install if the build fails." >&2
        fi
        jdk_home="${JDK8_HOME:-$(dirname "$(dirname "${javac_bin}")")}"

        # Clone (or update) the upstream repo at the release tag, into BENCH_WORK.
        if [ ! -d "${JT_SRC_DIR}/.git" ]; then
            echo "    cloning ${JAVA_TRON_REPO_URL} @ ${JAVA_TRON_TAG}…"
            rm -rf "${JT_SRC_DIR}"
            if ! git clone --depth 1 --branch "${JAVA_TRON_TAG}" \
                    "${JAVA_TRON_REPO_URL}" "${JT_SRC_DIR}"; then
                echo "ERROR: git clone of java-tron @ ${JAVA_TRON_TAG} failed." >&2
                exit 1
            fi
        else
            echo "    java-tron source already present at ${JT_SRC_DIR}; checking out ${JAVA_TRON_TAG}…"
            ( cd "${JT_SRC_DIR}" && git fetch --tags --depth 1 origin "${JAVA_TRON_TAG}" \
                && git checkout -q "${JAVA_TRON_TAG}" ) || {
                echo "ERROR: could not check out ${JAVA_TRON_TAG} in ${JT_SRC_DIR}." >&2
                exit 1
            }
        fi

        echo "    building FullNode jar with ${jdk_home} (this takes a while)…"
        if ! ( cd "${JT_SRC_DIR}" \
                 && JAVA_HOME="${jdk_home}" PATH="${jdk_home}/bin:${PATH}" \
                    ./gradlew :framework:buildFullNodeJar -x test \
                       -Dorg.gradle.java.home="${jdk_home}" ); then
            echo "ERROR: java-tron gradle build failed." >&2
            exit 1
        fi
        built="${JT_SRC_DIR}/framework/build/libs/FullNode.jar"
        if [ ! -f "${built}" ]; then
            echo "ERROR: build finished but ${built} is missing." >&2
            exit 1
        fi
        mkdir -p "$(dirname "${JT_BUILT_JAR}")"
        cp "${built}" "${JT_BUILT_JAR}"
        echo "    ok: ${JT_BUILT_JAR} (vanilla ${JAVA_TRON_TAG})"
    fi
fi

# ===========================================================================
# (c) Verify / locate the snapshot. READ-ONLY -- never modified by the suite.
# ===========================================================================
if want snapshot; then
    echo "==> [snapshot] locating a LiteFullNode snapshot…"
    if [ -d "${SNAPSHOT_PATH}/database" ]; then
        echo "    ok: ${SNAPSHOT_PATH} (stores under database/)"
    elif [ -n "${SNAPSHOT_URL}" ]; then
        echo "    SNAPSHOT_PATH not present; downloading SNAPSHOT_URL…"
        echo "    ${SNAPSHOT_URL}"
        dl_dir="${BENCH_WORK}/snapshot-download"
        mkdir -p "${dl_dir}"
        archive="${dl_dir}/snapshot.archive"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --retry 3 -o "${archive}" "${SNAPSHOT_URL}" || {
                echo "ERROR: download failed." >&2; exit 1; }
        elif command -v wget >/dev/null 2>&1; then
            wget -O "${archive}" "${SNAPSHOT_URL}" || {
                echo "ERROR: download failed." >&2; exit 1; }
        else
            echo "ERROR: neither curl nor wget is available to download SNAPSHOT_URL." >&2
            exit 1
        fi
        echo "    extracting into ${SNAPSHOT_PATH}…"
        mkdir -p "${SNAPSHOT_PATH}"
        case "${SNAPSHOT_URL}" in
            *.tar.gz|*.tgz) tar -xzf "${archive}" -C "${SNAPSHOT_PATH}" ;;
            *.tar)          tar -xf  "${archive}" -C "${SNAPSHOT_PATH}" ;;
            *.tar.lz4)      command -v lz4 >/dev/null 2>&1 \
                              && lz4 -dc "${archive}" | tar -xf - -C "${SNAPSHOT_PATH}" \
                              || { echo "ERROR: .tar.lz4 needs the lz4 tool." >&2; exit 1; } ;;
            *) echo "ERROR: unknown archive type for ${SNAPSHOT_URL}; extract it manually" >&2
               echo "       to ${SNAPSHOT_PATH} (so that ${SNAPSHOT_PATH}/database/ exists)." >&2
               exit 1 ;;
        esac
        # Some archives nest the snapshot one level down; find the database/ dir.
        if [ ! -d "${SNAPSHOT_PATH}/database" ]; then
            inner="$(find "${SNAPSHOT_PATH}" -maxdepth 3 -type d -name database 2>/dev/null | head -1)"
            if [ -n "${inner}" ]; then
                echo "    note: snapshot extracted to $(dirname "${inner}"); set SNAPSHOT_PATH there." >&2
                echo "          (database/ found at ${inner})" >&2
            fi
        fi
        [ -d "${SNAPSHOT_PATH}/database" ] || {
            echo "ERROR: after extraction, ${SNAPSHOT_PATH}/database/ is still missing." >&2
            exit 1; }
        echo "    ok: ${SNAPSHOT_PATH}"
    else
        cat >&2 <<EOF
ERROR: no snapshot found and no SNAPSHOT_URL to download one.

The benchmark needs a TRON LiteFullNode RocksDB snapshot (java-format; its
stores live under <snapshot>/database/). Supply one of:

  * SNAPSHOT_PATH=/path/to/snapshot   (a snapshot you already have), or
  * SNAPSHOT_URL=https://.../snap.tgz (a snapshot archive to download).

Public mainnet LiteFullNode snapshots are published by the TRON community
(e.g. the snapshot index at http://34.86.86.229/). Choose a LiteFullNode
(not a full archive) snapshot. The suite reads it READ-ONLY and copies it into
BENCH_WORK; it never modifies your snapshot.

The snapshot's head should sit at (FROM - 1) = $((FROM - 1)) for the default
sync range; any range works if you set FROM to (snapshot_head + 1).
EOF
        exit 1
    fi
fi

# ===========================================================================
# (d) Fetch the decode-dimension block corpus (OPTIONAL).
#
#     The corpus is a length-prefixed [int32-be len][Block bytes] stream of the
#     [FROM, TO] blocks in ascending order (the format replay-blocks/bench-decode
#     read). It must hold byte-exact Block protobufs so both engines decode the
#     identical bytes. fetch_corpus.py pulls those bytes via grpcurl from a
#     public mainnet gRPC node (GetBlockByNum2 returns the exact Block proto).
#     If BLOCKS_FILE already exists it is kept; if no fetch tool is present the
#     step is skipped with instructions (decode is an optional dimension).
# ===========================================================================
if want corpus; then
    echo "==> [corpus] preparing the decode block corpus…"
    if [ -f "${BLOCKS_FILE}" ]; then
        echo "    already present: ${BLOCKS_FILE} (delete it to refetch)"
    else
        mkdir -p "$(dirname "${BLOCKS_FILE}")"
        fetcher="${BENCH_DIR}/decode/fetch_corpus.py"
        if command -v python3 >/dev/null 2>&1 && [ -f "${fetcher}" ]; then
            echo "    fetching blocks [${FROM}, ${TO}] -> ${BLOCKS_FILE}…"
            if python3 "${fetcher}" --from "${FROM}" --to "${TO}" --out "${BLOCKS_FILE}"; then
                echo "    ok: ${BLOCKS_FILE}"
            else
                echo "    WARNING: corpus fetch failed; the decode dimension will be skipped." >&2
                echo "             supply your own corpus with BLOCKS_FILE=/path/to.blocks" >&2
                echo "             (length-prefixed [int32-be len][Block bytes], ascending)." >&2
            fi
        else
            echo "    note: no python3 / fetcher available; skipping corpus fetch." >&2
            echo "          the decode dimension is optional. To run it, supply a corpus:" >&2
            echo "            BLOCKS_FILE=/path/to/blocks.blocks  (length-prefixed Block stream)" >&2
        fi
    fi
fi

echo
echo "==> bootstrap complete. Next: bench/run.sh"
