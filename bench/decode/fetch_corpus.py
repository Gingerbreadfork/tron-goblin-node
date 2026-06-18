#!/usr/bin/env python3
"""fetch_corpus.py -- build the decode-dimension block corpus, portably.

The decode benchmark (bench/decode/) replays a fixed prefix of a length-prefixed
block corpus through both engines. The corpus must hold BYTE-EXACT canonical
`Block` protobufs so the Rust (`tron-node bench-decode`) and java (`DecodeBench`)
sides decode the identical bytes -- the `txs=` count both report is the built-in
cross-check that they walked the same transactions.

This fetcher produces that file from a PUBLIC mainnet gRPC node, with no
dependency on any private infrastructure or pre-cached `.blocks` file. It uses
`grpcurl` (https://github.com/fullstorydev/grpcurl) -- a single static binary,
the standard way to call a gRPC service from a script -- to invoke the TRON
`Wallet.GetBlockByNum2` method and emit each block's canonical protobuf bytes,
which it writes length-prefixed.

Output format (consumed by `tron-node bench-decode` / `replay-blocks` and
`DecodeBench`): a repeating stream of

    [ int32 big-endian length ][ length bytes of canonical Block protobuf ]

in ascending block order, EOF-terminated.

It drives grpcurl in BINARY protobuf mode (`-format protobuf`): the request
message is fed as raw protobuf on stdin (`-d @`) and grpcurl writes the response
message's wire bytes verbatim to stdout. Server reflection supplies the schema,
so no .proto files are needed, and the stdout bytes are exactly the canonical
`Block` wire encoding. (`-format protobuf` is supported by grpcurl >= 1.8.)

If grpcurl is unavailable or the node cannot return canonical bytes, this exits
non-zero. The decode dimension is OPTIONAL: bootstrap.sh tolerates a failure and
prints how to supply your own corpus via BLOCKS_FILE=/path/to.blocks.

Usage:
    fetch_corpus.py --from N --to N --out FILE
        [--endpoint host:port]   gRPC node (default: a public mainnet node)
        [--grpcurl PATH]         grpcurl binary (default: grpcurl on PATH)
        [--plaintext | --tls]    transport security (default: --plaintext)
"""

import argparse
import shutil
import struct
import subprocess
import sys


# A public mainnet gRPC node, used only when --endpoint is not given. Override
# freely; any mainnet FullNode exposing the gRPC Wallet service works.
DEFAULT_ENDPOINT = "grpc.trongrid.io:50051"

# Returns the full Block message (the "2" variant carries the transactions
# list). Re-serializing it yields the canonical wire bytes.
GRPC_METHOD = "protocol.Wallet/GetBlockByNum2"


def parse_args():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--from", dest="frm", type=int, required=True,
                   help="first block number (inclusive)")
    p.add_argument("--to", type=int, required=True,
                   help="last block number (inclusive)")
    p.add_argument("--out", required=True, help="output .blocks file")
    p.add_argument("--endpoint", default=DEFAULT_ENDPOINT,
                   help="gRPC node host:port (default: %(default)s)")
    p.add_argument("--grpcurl", default="grpcurl",
                   help="grpcurl binary (default: %(default)s on PATH)")
    sec = p.add_mutually_exclusive_group()
    sec.add_argument("--plaintext", dest="plaintext", action="store_true",
                     default=True, help="plaintext gRPC (default)")
    sec.add_argument("--tls", dest="plaintext", action="store_false",
                     help="TLS gRPC (for endpoints that require it)")
    return p.parse_args()


def fetch_block_bytes(args, num):
    """Return the canonical serialized `Block` protobuf for block `num`.

    Drives grpcurl in binary protobuf mode: the request message is fed on stdin
    (`-d @`) as raw protobuf and grpcurl writes the response message's wire
    bytes verbatim to stdout (server reflection supplies the schema), which are
    exactly the canonical `Block.toByteArray()` bytes. Raises RuntimeError on
    any failure.
    """
    cmd = [args.grpcurl]
    if args.plaintext:
        cmd.append("-plaintext")
    cmd += [
        # Binary protobuf on both sides; "@" reads the request from stdin.
        "-format", "protobuf",
        "-d", "@",
        args.endpoint,
        GRPC_METHOD,
    ]
    try:
        res = subprocess.run(cmd, input=_num_request_bytes(num),
                             capture_output=True, timeout=60)
    except FileNotFoundError:
        raise RuntimeError(
            "grpcurl not found (install it or pass --grpcurl PATH)")
    except subprocess.TimeoutExpired:
        raise RuntimeError("grpcurl timed out fetching block %d" % num)
    if res.returncode != 0:
        raise RuntimeError(
            "grpcurl failed for block %d: %s"
            % (num, res.stderr.decode("utf-8", "replace").strip()))
    if not res.stdout:
        raise RuntimeError("empty response for block %d" % num)
    return res.stdout


def _num_request_bytes(num):
    """Canonical NumberMessage{ int64 num = 1 } as raw protobuf bytes.

    Fed to grpcurl on stdin under `-format protobuf` so the request is
    byte-exact. NumberMessage has a single field: tag 0x08 (field 1, varint)
    followed by the varint-encoded number.
    """
    out = bytearray([0x08])
    n = num
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def main():
    args = parse_args()
    if args.to < args.frm:
        sys.stderr.write("fetch_corpus.py: --to must be >= --from\n")
        return 2
    if shutil.which(args.grpcurl) is None:
        sys.stderr.write(
            "fetch_corpus.py: '%s' not found. Install grpcurl "
            "(https://github.com/fullstorydev/grpcurl) or supply a corpus via "
            "BLOCKS_FILE.\n" % args.grpcurl)
        return 1

    total = args.to - args.frm + 1
    written = 0
    try:
        with open(args.out, "wb") as fh:
            for num in range(args.frm, args.to + 1):
                raw = fetch_block_bytes(args, num)
                fh.write(struct.pack(">i", len(raw)))
                fh.write(raw)
                written += 1
                if written % 500 == 0 or written == total:
                    sys.stderr.write(
                        "fetch_corpus.py: %d/%d blocks\n" % (written, total))
    except RuntimeError as e:
        sys.stderr.write("fetch_corpus.py: %s\n" % e)
        return 1
    sys.stderr.write("fetch_corpus.py: wrote %d blocks to %s\n"
                     % (written, args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
