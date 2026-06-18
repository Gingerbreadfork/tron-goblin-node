// DecodeBench -- the java-tron side of the "tron-goblin-node vs java-tron"
// DECODE-throughput microbenchmark.
//
// Measures pure protobuf parse + per-transaction contract-parameter decode for
// the canonical TRON Block, using the VANILLA java-tron classes on the FullNode
// classpath (org.tron.protos.*, the generated SmartContract/Balance/AssetIssue
// outer classes, and the bundled protobuf-java runtime). No instrumentation, no
// chain state, no RocksDB, no execution -- only the parse work every node does
// on the hot path before it can apply anything.
//
// It loads the same length-prefixed block corpus the Rust side loads:
//
//     [ int32 big-endian length ][ length bytes of Block protobuf ]   (repeated)
//
// into memory (untimed), runs JIT-warmup iterations that are NOT counted, then
// times one measured pass and reports blocks/sec + txs/sec.
//
// === Decode scope (kept byte-for-byte identical to the Rust microbench) ===
//
// For each frame in the corpus, per measured iteration:
//   1. Protocol.Block.parseFrom(bytes)        -- full Block protobuf parse.
//   2. iterate block.getTransactionsList()    -- touch every transaction.
//   3. for the FIRST contract of each tx:
//        - read contract.getType();
//        - unpack the typed parameter Any:
//            TransferContract        (native TRX transfer),
//            TransferAssetContract   (TRC-10 transfer),
//            TriggerSmartContract    (contract call);
//        - for TriggerSmartContract: read the 4-byte selector, map it to a
//          method name, and ABI-decode the USDT transfer/transferFrom amount.
//
// This is exactly what the Rust mempool/explore `decode_tx_summary` does, so the
// two engines decode the SAME logical work over the SAME bytes.
//
// USAGE
//   java DecodeBench <blocks-file> <count> [warmup-iters] [measured-iters]
//
//   blocks-file     path to the length-prefixed .blocks corpus
//   count           number of leading blocks to load into memory
//   warmup-iters    full decode passes run before timing (default 2), excluded
//   measured-iters  timed decode passes (default 1); the report divides total
//                   timed work by elapsed so blocks/sec is per-block throughput
//
// Output (last line, machine-parseable, mirrors the Rust subcommand):
//   bench-decode: blocks=N txs=M elapsed_s=S blocks_per_sec=.. txs_per_sec=..

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import com.google.protobuf.Any;

import org.tron.protos.Protocol.Block;
import org.tron.protos.Protocol.Transaction;
import org.tron.protos.Protocol.Transaction.Contract;
import org.tron.protos.Protocol.Transaction.Contract.ContractType;
import org.tron.protos.contract.BalanceContract.TransferContract;
import org.tron.protos.contract.AssetIssueContractOuterClass.TransferAssetContract;
import org.tron.protos.contract.SmartContractOuterClass.TriggerSmartContract;

public final class DecodeBench {

  // The USDT TRC-20 contract address (21-byte TRON address, hex) -- the same
  // constant the Rust explore module keys USDT classification on.
  private static final String USDT_ADDRESS_HEX = "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

  // TRC-20 selectors the Rust side ABI-decodes amounts for.
  private static final byte[] SEL_TRANSFER = {(byte) 0xa9, 0x05, (byte) 0x9c, (byte) 0xbb};
  private static final byte[] SEL_TRANSFER_FROM = {0x23, (byte) 0xb8, 0x72, (byte) 0xdd};

  // A cheap sink so the JIT cannot dead-code-eliminate the decode work. Read
  // out at the end so it is observably live.
  private static long sink = 0;

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println(
          "usage: java DecodeBench <blocks-file> <count> [warmup-iters] [measured-iters]");
      System.exit(2);
    }
    String path = args[0];
    int count = Integer.parseInt(args[1]);
    int warmup = args.length >= 3 ? Integer.parseInt(args[2]) : 2;
    int measured = args.length >= 4 ? Integer.parseInt(args[3]) : 1;
    if (measured < 1) {
      measured = 1;
    }

    // === Phase 1: load the corpus into memory (untimed) ===
    List<byte[]> corpus = loadCorpus(path, count);
    System.err.printf("DecodeBench: loaded %d blocks into memory (requested %d)%n",
        corpus.size(), count);

    // === JIT warmup (NOT timed) ===
    // Run full decode passes so the HotSpot JIT compiles the parse + unpack hot
    // methods before we measure. These iterations are discarded.
    for (int w = 0; w < warmup; w++) {
      long[] r = decodePass(corpus);
      // touch results so warmup is not optimized away
      sink += r[0] + r[1];
    }
    System.err.printf("DecodeBench: completed %d warmup pass(es)%n", warmup);

    // === Phase 2: measured decode passes (timed) ===
    long blocks = 0;
    long txs = 0;
    long t0 = System.nanoTime();
    for (int m = 0; m < measured; m++) {
      long[] r = decodePass(corpus);
      blocks += r[0];
      txs += r[1];
    }
    long t1 = System.nanoTime();

    double elapsedTotal = (t1 - t0) / 1e9;
    // Report per-single-pass throughput: divide the elapsed across the measured
    // passes so blocks/sec is "blocks decoded per wall second" regardless of how
    // many passes were averaged. blocks/txs reported are per single pass.
    double elapsedPerPass = elapsedTotal / measured;
    long blocksPerPass = blocks / measured;
    long txsPerPass = txs / measured;

    double bps = elapsedPerPass > 0 ? blocksPerPass / elapsedPerPass : 0.0;
    double tps = elapsedPerPass > 0 ? txsPerPass / elapsedPerPass : 0.0;

    // Keep the sink observably live so the JIT cannot elide the decode work.
    System.err.printf("DecodeBench: sink=%d (ignore)%n", sink);

    // Machine-parseable final line (identical shape to the Rust subcommand).
    System.out.printf(
        "bench-decode: blocks=%d txs=%d elapsed_s=%.3f blocks_per_sec=%.1f txs_per_sec=%.1f%n",
        blocksPerPass, txsPerPass, elapsedPerPass, bps, tps);
  }

  // Read up to `count` length-prefixed frames into memory. I/O lives here so it
  // is excluded from the timed window. Frame format is the canonical TRON block
  // corpus the Rust side also reads: [int32 big-endian length][Block bytes].
  private static List<byte[]> loadCorpus(String path, int count) throws IOException {
    List<byte[]> out = new ArrayList<>();
    try (DataInputStream in =
        new DataInputStream(new BufferedInputStream(new FileInputStream(path), 1 << 20))) {
      while (out.size() < count) {
        int len;
        try {
          len = in.readInt(); // big-endian int32 (DataInputStream is BE)
        } catch (java.io.EOFException eof) {
          break; // clean EOF at a frame boundary
        }
        if (len <= 0) {
          break; // 0-length terminator (or corrupt) -- stop
        }
        byte[] raw = new byte[len];
        in.readFully(raw);
        out.add(raw);
      }
    }
    return out;
  }

  // One full decode pass over the in-memory corpus. Returns {blocks, txs}.
  // Mirrors the Rust `decode_tx_summary` decode scope exactly.
  private static long[] decodePass(List<byte[]> corpus) {
    long blocks = 0;
    long txs = 0;
    long localSink = 0;
    for (byte[] raw : corpus) {
      final Block block;
      try {
        block = Block.parseFrom(raw);
      } catch (Exception e) {
        // A canonical corpus should never fail to parse; surface and stop.
        throw new RuntimeException("Block.parseFrom failed", e);
      }
      for (Transaction tx : block.getTransactionsList()) {
        localSink += decodeTx(tx);
        txs++;
      }
      localSink += block.getTransactionsCount();
      blocks++;
    }
    sink += localSink;
    return new long[] {blocks, txs};
  }

  // Decode the first contract of one transaction, mirroring decode_tx_summary:
  // unpack the typed parameter, and for a contract call extract the selector,
  // map it to a method name, and ABI-decode the USDT amount. Returns a small
  // value folded into the sink so nothing is dead-code-eliminated.
  private static long decodeTx(Transaction tx) {
    Transaction.raw raw = tx.getRawData();
    if (raw.getContractCount() == 0) {
      return 0;
    }
    Contract contract = raw.getContract(0);
    Any param = contract.getParameter();
    long acc = contract.getTypeValue();
    try {
      ContractType type = contract.getType();
      switch (type) {
        case TransferContract: {
          TransferContract c = param.unpack(TransferContract.class);
          acc += c.getAmount();
          acc += c.getToAddress().size();
          break;
        }
        case TransferAssetContract: {
          TransferAssetContract c = param.unpack(TransferAssetContract.class);
          acc += c.getAmount();
          acc += c.getToAddress().size();
          break;
        }
        case TriggerSmartContract: {
          TriggerSmartContract c = param.unpack(TriggerSmartContract.class);
          acc += c.getCallValue();
          ByteString data = c.getData();
          if (data.size() >= 4) {
            byte[] sel = new byte[4];
            for (int i = 0; i < 4; i++) {
              sel[i] = data.byteAt(i);
            }
            acc += methodNameHash(sel);
            String contractHex = toHex(c.getContractAddress());
            if (USDT_ADDRESS_HEX.equals(contractHex)) {
              Long units = usdtAmount(data);
              if (units != null) {
                acc += units;
              }
            }
          }
          acc += c.getContractAddress().size();
          break;
        }
        default:
          // Other contract types: type read only (matches the Rust `_ => {}`).
          break;
      }
    } catch (Exception e) {
      // A malformed Any unpack -- count nothing extra (the Rust side silently
      // skips on a failed decode), but keep going.
    }
    return acc;
  }

  // Map a 4-byte selector to a method name and fold its length into the sink.
  // Mirrors explore::method_name's selector set so both sides do the same
  // selector->name work; the returned hash just keeps the result live.
  private static long methodNameHash(byte[] sel) {
    String name;
    if (eq(sel, (byte) 0xa9, 0x05, (byte) 0x9c, (byte) 0xbb)) {
      name = "transfer";
    } else if (eq(sel, 0x23, (byte) 0xb8, 0x72, (byte) 0xdd)) {
      name = "transferFrom";
    } else if (eq(sel, 0x09, 0x5e, (byte) 0xa7, (byte) 0xb3)) {
      name = "approve";
    } else if (eq(sel, 0x40, (byte) 0xc1, 0x0f, 0x19)) {
      name = "mint";
    } else if (eq(sel, 0x42, (byte) 0x96, 0x6c, 0x68)) {
      name = "burn";
    } else if (eq(sel, 0x38, (byte) 0xed, 0x17, 0x39)
        || eq(sel, 0x18, (byte) 0xcb, (byte) 0xaf, (byte) 0xe5)
        || eq(sel, 0x7f, (byte) 0xf3, 0x6a, (byte) 0xb5)
        || eq(sel, (byte) 0xfb, 0x3b, (byte) 0xdb, 0x41)) {
      name = "swap";
    } else if (eq(sel, 0x2e, 0x1a, 0x7d, 0x4d)) {
      name = "withdraw";
    } else if (eq(sel, (byte) 0xd0, (byte) 0xe3, 0x0d, (byte) 0xb0)) {
      name = "deposit";
    } else {
      name = "0x" + toHexBytes(sel);
    }
    return name.length();
  }

  // ABI-decode a USDT transfer / transferFrom amount, mirroring
  // explore::usdt_amount: take the low 128 bits (here, the low 64 bits suffice
  // to keep the work live) of the uint256 amount field at the selector-relative
  // offset. Returns null for any other selector.
  private static Long usdtAmount(ByteString data) {
    if (data.size() < 4) {
      return null;
    }
    byte[] sel = {data.byteAt(0), data.byteAt(1), data.byteAt(2), data.byteAt(3)};
    int amountOff;
    if (sameSel(sel, SEL_TRANSFER)) {
      amountOff = 4 + 32; // selector + to
    } else if (sameSel(sel, SEL_TRANSFER_FROM)) {
      amountOff = 4 + 32 + 32; // selector + from + to
    } else {
      return null;
    }
    if (data.size() < amountOff + 32) {
      return null;
    }
    // Low 64 bits of the 32-byte big-endian amount word (bytes 24..32 of the
    // field). Reading the amount word is the ABI param decode being measured.
    long v = 0;
    for (int i = amountOff + 24; i < amountOff + 32; i++) {
      v = (v << 8) | (data.byteAt(i) & 0xffL);
    }
    return v;
  }

  private static boolean sameSel(byte[] a, byte[] b) {
    for (int i = 0; i < 4; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  private static boolean eq(byte[] sel, int b0, int b1, int b2, int b3) {
    return sel[0] == (byte) b0 && sel[1] == (byte) b1 && sel[2] == (byte) b2 && sel[3] == (byte) b3;
  }

  private static final char[] HEX = "0123456789abcdef".toCharArray();

  private static String toHex(ByteString bs) {
    StringBuilder sb = new StringBuilder(bs.size() * 2);
    for (int i = 0; i < bs.size(); i++) {
      int v = bs.byteAt(i) & 0xff;
      sb.append(HEX[v >>> 4]).append(HEX[v & 0xf]);
    }
    return sb.toString();
  }

  private static String toHexBytes(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte value : b) {
      int v = value & 0xff;
      sb.append(HEX[v >>> 4]).append(HEX[v & 0xf]);
    }
    return sb.toString();
  }

  private DecodeBench() {}
}
