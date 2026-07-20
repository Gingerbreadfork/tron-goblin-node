//! Differential check of `BatchValidateSign` (0x09) and `ValidateMultiSign`
//! (0x0a) against a reference implementation derived independently from
//! java-tron's `PrecompiledContracts.java` (BatchValidateSign lines
//! 1016-1133, ValidateMultiSign lines 935-1014, helpers 356-415), NOT from
//! our `precompiles.rs`. The reference deliberately re-implements signature
//! recovery from `ECDSASignature.validateComponents` + `Rsv.fromSignature`
//! rather than calling our shared helper, so a defaults-differ bug in a
//! parsing/crypto library (the class that produced the high-s ecrecover
//! bug) is caught instead of cancelled out.
//!
//! The java contract the reference encodes:
//!
//! * `DataWord.parseArray` floor-splits calldata into 32-byte words and
//!   DROPS a trailing partial word; `extractBytes` reads the RAW calldata
//!   (partial tail included) and zero-pads past the end
//!   (`Arrays.copyOfRange` semantics), throwing only when `from` is
//!   negative or beyond `data.length`.
//! * `intValueSafe` clamps to `Integer.MAX_VALUE` when the word occupies
//!   more than 4 bytes or has the int sign bit set.
//! * Recovery (`recoverAddrBySign`): input shorter than 65 bytes yields the
//!   empty array; `v` is a SIGNED byte, `v < 27` adds 27 (wrapping), and
//!   only 27/28 survive `validateComponents`; `r` and `s` must each be in
//!   `[1, n)` — high-s is legal; failure yields java `null`.
//! * `BatchValidateSign.execute` wraps everything in `catch (Throwable)` →
//!   any parse error returns 32 zero bytes. Result byte `i` (from the LEFT)
//!   is 1 iff the last 20 bytes of `addresses[i]` equal the last 20 bytes
//!   of the recovered 21-byte address.
//! * `ValidateMultiSign.execute` has NO catch around parsing: an
//!   out-of-range word index escapes as an uncaught throw that costs the
//!   calling frame all its energy. Only the permission/weight block is
//!   caught (→ DATA_FALSE), including the NPE from `merge(null, sign)` when
//!   recovery fails.
//! * Post-#94 (`ALLOW_TVM_SELFDESTRUCT_RESTRICTION`), `extractSigArray`
//!   reads a fixed 65 bytes per element (the per-element length word is
//!   never read) and an up-front size probe rejects arrays over the cap —
//!   but that probe itself indexes `words[offset]`, so an out-of-range
//!   offset THROWS post-#94 where pre-#94's `extractBytesArray` guard
//!   returned an empty array (→ DATA_FALSE).
//! * Duplicate handling in ValidateMultiSign skips only an exact
//!   (addr ‖ sig) pair: the same key signing with two different signatures
//!   (e.g. low-s and high-s of one signature) is counted TWICE.
//! * Energy: batch `((len/32 - 5) / 6) * 1500`, multi
//!   `((len/32 - 5) / 5) * 1500`, both with java's truncating division —
//!   multi goes NEGATIVE (-1500) for calldata shorter than 32 bytes, and
//!   `Program.callToPrecompiledAddress` really refunds that negative cost.
//!
//! Untestable corner (documented, not asserted): a declared array/element
//! length large enough that java's up-front `new byte[len][]` /
//! `copyOfRange` allocation throws `OutOfMemoryError`. For
//! BatchValidateSign the `catch (Throwable)` turns that into the same 32
//! zero bytes as any other failure, but for pre-#94 ValidateMultiSign the
//! Error escapes even `VM.play` — java-side behavior is a dead executor
//! thread, not a consensus result. The corpus stays below allocation sizes
//! where the two models diverge.

use std::collections::HashMap;

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use tron_crypto::address::Address;
use tron_crypto::hash::{keccak256, sha256};
use tron_proto::{Account, Key, Permission};
use tron_tvm::{EvmContext, EvmContextError, PrecompileError, PrecompileImpl};

// =============================================================================
// Test context
// =============================================================================

struct Ctx {
    accounts: HashMap<[u8; 21], Account>,
    restriction: bool,
}

impl Ctx {
    fn new(restriction: bool, accounts: HashMap<[u8; 21], Account>) -> Self {
        Self { accounts, restriction }
    }
}

impl EvmContext for Ctx {
    fn caller(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn callee(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn get_account(&self, a: &Address) -> Result<Option<Account>, EvmContextError> {
        Ok(self.accounts.get(a.as_bytes()).cloned())
    }
    fn get_witness(&self, _: &Address) -> Result<Option<tron_proto::Witness>, EvmContextError> {
        Ok(None)
    }
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError> {
        if key == b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION" {
            return Ok(Some(i64::from(self.restriction)));
        }
        Ok(None)
    }
    fn block_number(&self) -> i64 {
        0
    }
    fn block_timestamp_ms(&self) -> i64 {
        0
    }
    fn all_witnesses(&self) -> Result<Vec<tron_proto::Witness>, EvmContextError> {
        Ok(vec![])
    }
    fn get_delegated_resource(
        &self,
        _: &Address,
        _: &Address,
    ) -> Result<Option<tron_proto::DelegatedResource>, EvmContextError> {
        Ok(None)
    }
    fn dynamic_energy_factor(&self, _: &Address) -> Result<i64, EvmContextError> {
        Ok(0)
    }
}

// =============================================================================
// Reference implementation (derived from java-tron source, see module doc)
// =============================================================================

/// secp256k1 group order n.
const N_BYTES: [u8; 32] =
    hex_literal::hex!("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
/// floor((n-1)/2): s is "high" iff s > this.
const HALF_N_BYTES: [u8; 32] =
    hex_literal::hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0");

/// Models a java exception escaping the precompile body.
///
/// `Aioobe` is the deterministic kind (bad word index, negative
/// `copyOfRange` start). `Oom` models a declared array count or element
/// length so large that java's up-front `new byte[len]` /`new byte[len][]`
/// allocation throws `OutOfMemoryError` — for a clamped `intValueSafe`
/// (== `Integer.MAX_VALUE`) that is guaranteed on HotSpot (over the VM
/// array-size limit), while mid-range sizes are HEAP-DEPENDENT in java and
/// therefore not consensus-comparable at all; the corpus only produces the
/// clamped kind. BatchValidateSign catches both (→ 32 zero bytes);
/// pre-#94 ValidateMultiSign lets the Error escape even `VM.play`, so
/// those cases are skipped rather than asserted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Thrown {
    Aioobe,
    Oom,
}

/// java `recoverAddrBySign` outcome: `new byte[0]` for short input, `null`
/// for anything invalid, or the 21-byte 0x41-prefixed address.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rec {
    Empty,
    Null,
    Addr([u8; 21]),
}

fn is_zero32(b: &[u8; 32]) -> bool {
    b.iter().all(|&x| x == 0)
}

/// Big-endian fixed-width byte compare == numeric compare.
fn lt(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a < b
}

/// n - s over big-endian bytes (s must be in [1, n)).
fn n_minus(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(N_BYTES[i]) - i16::from(s[i]) - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// java `PrecompiledContracts.recoverAddrBySign` + `Rsv.fromSignature` +
/// `ECDSASignature.validateComponents` + `ECKey.signatureToAddress` +
/// `Hash.sha3omit12`, re-derived. High-s recovery is performed by
/// normalizing s and flipping the recovery parity, which is
/// mathematically identical to java's direct recovery from (r, s, v):
/// for R' = -R, r^-1·(s·R - z·G) = r^-1·((n-s)·R' - z·G).
fn ref_recover(sign: &[u8], hash: &[u8; 32]) -> Rec {
    if sign.len() < 65 {
        return Rec::Empty;
    }
    let r: [u8; 32] = sign[0..32].try_into().unwrap();
    let s: [u8; 32] = sign[32..64].try_into().unwrap();
    // java: `byte v = sign[64]; if (v < 27) v += 27;` — SIGNED compare,
    // wrapping byte add.
    let v_raw = sign[64] as i8;
    let v = if v_raw < 27 { v_raw.wrapping_add(27) } else { v_raw };
    if v != 27 && v != 28 {
        return Rec::Null;
    }
    // validateComponents: 1 <= r < n, 1 <= s < n. High-s is PERMITTED.
    if is_zero32(&r) || is_zero32(&s) || !lt(&r, &N_BYTES) || !lt(&s, &N_BYTES) {
        return Rec::Null;
    }
    let mut recid = (v - 27) as u8;
    let s_low = if lt(&HALF_N_BYTES, &s) {
        recid ^= 1;
        n_minus(&s)
    } else {
        s
    };
    let Ok(sig) = Signature::from_scalars(r, s_low) else {
        return Rec::Null;
    };
    let Some(recovery_id) = RecoveryId::from_byte(recid) else {
        return Rec::Null;
    };
    match VerifyingKey::recover_from_prehash(hash, &sig, recovery_id) {
        Ok(vk) => {
            let point = vk.to_encoded_point(false);
            let h = keccak256(&point.as_bytes()[1..]);
            let mut a = [0u8; 21];
            a[0] = 0x41;
            a[1..].copy_from_slice(&h[12..]);
            Rec::Addr(a)
        }
        Err(_) => Rec::Null,
    }
}

/// java `DataWord.parseArray`: floor split, trailing partial word DROPPED.
fn java_words(data: &[u8]) -> Vec<[u8; 32]> {
    (0..data.len() / 32)
        .map(|i| data[i * 32..(i + 1) * 32].try_into().unwrap())
        .collect()
}

/// java `DataWord.intValueSafe`.
fn ivs(w: &[u8; 32]) -> i32 {
    if w[..28].iter().any(|&b| b != 0) {
        return i32::MAX;
    }
    let v = u32::from_be_bytes(w[28..32].try_into().unwrap());
    if v > i32::MAX as u32 {
        i32::MAX
    } else {
        v as i32
    }
}

/// `words[idx]` with java's AIOOBE modeled as `Thrown::Aioobe`.
fn get_word(words: &[[u8; 32]], idx: i32) -> Result<[u8; 32], Thrown> {
    if idx < 0 || idx as usize >= words.len() {
        return Err(Thrown::Aioobe);
    }
    Ok(words[idx as usize])
}

/// A declared size the corpus treats as java-OOM (see [`Thrown::Oom`]):
/// garbage control words always clamp to exactly `Integer.MAX_VALUE` via
/// `intValueSafe`, which is over HotSpot's array-size limit. Anything
/// between the crafted-corpus maximum (100 000) and this is heap-dependent
/// in java and is asserted unreachable instead of being modeled.
fn oom_size(len: i32) -> Result<(), Thrown> {
    if len == i32::MAX {
        return Err(Thrown::Oom);
    }
    assert!(
        len <= 1_000_000,
        "corpus produced a mid-range huge declared size ({len}); java behavior is heap-dependent"
    );
    Ok(())
}

/// java `extractBytes` = `Arrays.copyOfRange(data, from, from + len)`:
/// throws when `from` is negative or past the end; zero-pads when the
/// range overruns. Allocation happens after the `from` check.
fn ref_extract_bytes(data: &[u8], from: i32, len: i32) -> Result<Vec<u8>, Thrown> {
    if from < 0 || from as usize > data.len() {
        return Err(Thrown::Aioobe);
    }
    oom_size(len)?;
    let from = from as usize;
    let len = len as usize;
    let avail = (data.len() - from).min(len);
    let mut out = vec![0u8; len];
    out[..avail].copy_from_slice(&data[from..from + avail]);
    Ok(out)
}

/// java `extractSigArray` (post-#94): fixed 65-byte elements; the
/// per-element length word is never read.
fn ref_extract_sig_array(
    words: &[[u8; 32]],
    offset: i32,
    data: &[u8],
) -> Result<Vec<Vec<u8>>, Thrown> {
    if i64::from(offset) > words.len() as i64 - 1 {
        return Ok(vec![]);
    }
    let len = ivs(&words[offset as usize]);
    // java allocates `new byte[len][]` before the loop.
    oom_size(len)?;
    let mut out = Vec::new();
    for i in 0..len {
        let idx = offset.wrapping_add(i).wrapping_add(1);
        let bytes_offset = ivs(&get_word(words, idx)?) / 32;
        let start = bytes_offset.wrapping_add(offset).wrapping_add(2).wrapping_mul(32);
        out.push(ref_extract_bytes(data, start, 65)?);
    }
    Ok(out)
}

/// java `extractBytesArray` (pre-#94): per-element declared length.
fn ref_extract_bytes_array(
    words: &[[u8; 32]],
    offset: i32,
    data: &[u8],
) -> Result<Vec<Vec<u8>>, Thrown> {
    if i64::from(offset) > words.len() as i64 - 1 {
        return Ok(vec![]);
    }
    let len = ivs(&words[offset as usize]);
    // java allocates `new byte[len][]` before the loop.
    oom_size(len)?;
    let mut out = Vec::new();
    for i in 0..len {
        let idx = offset.wrapping_add(i).wrapping_add(1);
        let bytes_offset = ivs(&get_word(words, idx)?) / 32;
        let len_idx = offset.wrapping_add(bytes_offset).wrapping_add(1);
        let bytes_len = ivs(&get_word(words, len_idx)?);
        let start = bytes_offset.wrapping_add(offset).wrapping_add(2).wrapping_mul(32);
        out.push(ref_extract_bytes(data, start, bytes_len)?);
    }
    Ok(out)
}

/// java `extractBytes32Array`: inline 32-byte words, NO offset guard.
fn ref_extract_bytes32_array(words: &[[u8; 32]], offset: i32) -> Result<Vec<[u8; 32]>, Thrown> {
    let len = ivs(&get_word(words, offset)?);
    oom_size(len)?;
    let mut out = Vec::new();
    for i in 0..len {
        let idx = offset.wrapping_add(i).wrapping_add(1);
        out.push(get_word(words, idx)?);
    }
    Ok(out)
}

fn data_false() -> Vec<u8> {
    vec![0u8; 32]
}

fn data_true() -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[31] = 1;
    v
}

/// java `BatchValidateSign`: every failure (thrown or checked) is 32 zero
/// bytes, so the reference collapses `Thrown` into that.
fn ref_batch(input: &[u8], restriction: bool) -> Vec<u8> {
    ref_batch_inner(input, restriction).unwrap_or_else(|_| data_false())
}

fn ref_batch_inner(input: &[u8], restriction: bool) -> Result<Vec<u8>, Thrown> {
    let words = java_words(input);
    let hash = get_word(&words, 0)?;
    let sig_off = ivs(&get_word(&words, 1)?) / 32;
    let addr_off = ivs(&get_word(&words, 2)?) / 32;
    let signatures = if restriction {
        let sig_size = ivs(&get_word(&words, sig_off)?);
        let addr_size = ivs(&get_word(&words, addr_off)?);
        if sig_size > 16 || addr_size > 16 {
            return Ok(data_false());
        }
        ref_extract_sig_array(&words, sig_off, input)?
    } else {
        ref_extract_bytes_array(&words, sig_off, input)?
    };
    let addresses = ref_extract_bytes32_array(&words, addr_off)?;
    let cnt = signatures.len();
    if cnt == 0 || cnt > 16 || cnt != addresses.len() {
        return Ok(data_false());
    }
    let mut res = vec![0u8; 32];
    for i in 0..cnt {
        if let Rec::Addr(a) = ref_recover(&signatures[i], &hash) {
            // equalAddressByteArray: last 20 bytes of each side.
            if a[1..21] == addresses[i][12..32] {
                res[i] = 1;
            }
        }
    }
    Ok(res)
}

/// java `ValidateMultiSign` result: either a returned word or an uncaught
/// throw that costs the calling frame all its energy. `None` marks the one
/// square that is not java-consensus-defined: an `OutOfMemoryError` from a
/// clamped declared size, which kills the executor thread instead of
/// producing a result — those cases are skipped, not asserted.
fn ref_multi(
    input: &[u8],
    restriction: bool,
    accounts: &HashMap<[u8; 21], Account>,
    synthesize_default: bool,
) -> Option<RefMulti> {
    match ref_multi_inner(input, restriction, accounts, synthesize_default) {
        Ok(bytes) => Some(RefMulti::Out(bytes)),
        Err(Thrown::Aioobe) => Some(RefMulti::Throw),
        Err(Thrown::Oom) => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RefMulti {
    Out(Vec<u8>),
    Throw,
}

fn ref_multi_inner(
    input: &[u8],
    restriction: bool,
    accounts: &HashMap<[u8; 21], Account>,
    synthesize_default: bool,
) -> Result<Vec<u8>, Thrown> {
    let words = java_words(input);
    // words[0..3] are read before any try-block: short input THROWS.
    let addr_word = get_word(&words, 0)?;
    let perm_id = ivs(&get_word(&words, 1)?);
    let msg = get_word(&words, 2)?;
    let sig_off = ivs(&get_word(&words, 3)?) / 32;

    let mut addr21 = [0u8; 21];
    addr21[0] = 0x41;
    addr21[1..].copy_from_slice(&addr_word[12..32]);

    // hash = SHA256(address(21) || int(permissionId) BE(4) || data(32)).
    let mut preimage = Vec::with_capacity(57);
    preimage.extend_from_slice(&addr21);
    preimage.extend_from_slice(&perm_id.to_be_bytes());
    preimage.extend_from_slice(&msg);
    let hash = sha256(&preimage);

    if restriction {
        // The size probe itself indexes words[sig_off]: OOB THROWS here,
        // where pre-#94 falls into extractBytesArray's empty-array guard.
        let sig_size = ivs(&get_word(&words, sig_off)?);
        if sig_size > 5 {
            return Ok(data_false());
        }
    }
    let signatures = if restriction {
        ref_extract_sig_array(&words, sig_off, input)?
    } else {
        ref_extract_bytes_array(&words, sig_off, input)?
    };
    if signatures.is_empty() || signatures.len() > 5 {
        return Ok(data_false());
    }
    let Some(account) = accounts.get(&addr21) else {
        return Ok(data_false());
    };
    // From here on java is inside `try { .. } catch (Throwable)` → any
    // error is DATA_FALSE, never a throw.
    let Some(permission) = ref_permission_by_id(account, perm_id, synthesize_default) else {
        return Ok(data_false());
    };
    let mut total: i64 = 0;
    let mut executed: Vec<Vec<u8>> = Vec::new();
    for sign in &signatures {
        let rec_bytes: Vec<u8> = match ref_recover(sign, &hash) {
            // null → NPE in merge(recoveredAddr, sign) → caught → FALSE.
            Rec::Null => return Ok(data_false()),
            Rec::Empty => vec![],
            Rec::Addr(a) => a.to_vec(),
        };
        let mut merged = rec_bytes.clone();
        merged.extend_from_slice(sign);
        if executed.iter().any(|e| *e == rec_bytes) && executed.iter().any(|e| *e == merged) {
            // Only an exact (addr ‖ sig) duplicate is skipped; the same
            // address with a different signature falls through and is
            // counted AGAIN.
            continue;
        }
        let weight = permission
            .keys
            .iter()
            .find(|k| k.address == rec_bytes)
            .map_or(0, |k| k.weight);
        if weight == 0 {
            return Ok(data_false());
        }
        total = total.wrapping_add(weight);
        executed.push(merged);
        executed.push(rec_bytes);
    }
    if total >= permission.threshold {
        return Ok(data_true());
    }
    Ok(data_false())
}

/// java `AccountCapsule.getPermissionById`.
///
/// `synthesize_default` toggles java's `getDefaultPermission` fallback for
/// `id == 0`. Passing `false` yields the behavior our precompile actually
/// implements, which is how [`check_multi`] pins defect D1 precisely
/// instead of merely observing "the outputs differ".
fn ref_permission_by_id(
    account: &Account,
    id: i32,
    synthesize_default: bool,
) -> Option<Permission> {
    if id == 0 {
        if !synthesize_default {
            return account.owner_permission.clone();
        }
        return Some(account.owner_permission.clone().unwrap_or_else(|| Permission {
            r#type: 0,
            id: 0,
            permission_name: "owner".into(),
            threshold: 1,
            parent_id: 0,
            operations: vec![],
            // getDefaultPermission uses the account's STORED address bytes.
            keys: vec![Key { address: account.address.clone(), weight: 1 }],
        }));
    }
    if id == 1 {
        return account.witness_permission.clone();
    }
    account.active_permission.iter().find(|p| p.id == id).cloned()
}

/// java `getEnergyForData` for BatchValidateSign: `(len/32 - 5) / 6 * 1500`
/// with truncating division (never negative: -5/6 truncates to 0).
fn ref_batch_energy(len: usize) -> i64 {
    (len as i64 / 32 - 5) / 6 * 1500
}

/// java `getEnergyForData` for ValidateMultiSign: `(len/32 - 5) / 5 * 1500`
/// — NEGATIVE (-1500) for calldata under 32 bytes, and
/// `Program.callToPrecompiledAddress` genuinely refunds it.
fn ref_multi_energy(len: usize) -> i64 {
    (len as i64 / 32 - 5) / 5 * 1500
}

// =============================================================================
// Vector construction
// =============================================================================

fn sk(seed: u8) -> SigningKey {
    let mut b = [0u8; 32];
    b[31] = seed;
    SigningKey::from_bytes(&b.into()).unwrap()
}

fn addr_of(key: &SigningKey) -> [u8; 21] {
    let point = key.verifying_key().to_encoded_point(false);
    let h = keccak256(&point.as_bytes()[1..]);
    let mut a = [0u8; 21];
    a[0] = 0x41;
    a[1..].copy_from_slice(&h[12..]);
    a
}

/// 65-byte r ‖ s ‖ v signature over a 32-byte prehash, v ∈ {27, 28}.
fn sign65(key: &SigningKey, hash: &[u8; 32]) -> Vec<u8> {
    let (sig, recid) = key.sign_prehash_recoverable(hash).unwrap();
    let mut out = sig.to_bytes().to_vec();
    out.push(27 + recid.to_byte());
    out
}

/// The equally-valid high-s form: s → n - s, v parity flipped.
fn flip_s(sig65: &[u8]) -> Vec<u8> {
    let mut out = sig65.to_vec();
    let s: [u8; 32] = out[32..64].try_into().unwrap();
    out[32..64].copy_from_slice(&n_minus(&s));
    out[64] = if out[64] == 27 { 28 } else { 27 };
    out
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn addr_word(addr21: &[u8; 21]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&addr21[1..]);
    w
}

fn pad32(len: usize) -> usize {
    len.div_ceil(32) * 32
}

/// Canonical ABI `bytes[]` block: count word, relative element offsets,
/// then per-element length word + zero-padded content.
fn abi_bytes_array(elems: &[Vec<u8>]) -> Vec<u8> {
    let mut rel = Vec::new();
    let mut cursor = 32 * elems.len();
    for e in elems {
        rel.push(cursor as u64);
        cursor += 32 + pad32(e.len());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&word_u64(elems.len() as u64));
    for r in rel {
        out.extend_from_slice(&word_u64(r));
    }
    for e in elems {
        out.extend_from_slice(&word_u64(e.len() as u64));
        out.extend_from_slice(e);
        out.resize(out.len() + pad32(e.len()) - e.len(), 0);
    }
    out
}

/// Canonical BatchValidateSign calldata: hash, two head offsets, `bytes[]`
/// signature block, inline `bytes32[]` address block.
fn batch_input(hash: &[u8; 32], sigs: &[Vec<u8>], addr_words: &[[u8; 32]]) -> Vec<u8> {
    let sig_block = abi_bytes_array(sigs);
    let mut out = Vec::new();
    out.extend_from_slice(hash);
    out.extend_from_slice(&word_u64(0x60));
    out.extend_from_slice(&word_u64(0x60 + sig_block.len() as u64));
    out.extend_from_slice(&sig_block);
    out.extend_from_slice(&word_u64(addr_words.len() as u64));
    for w in addr_words {
        out.extend_from_slice(w);
    }
    out
}

/// Canonical ValidateMultiSign calldata: address word, permission id,
/// 32-byte message, head offset, `bytes[]` signature block.
fn multi_input(addr: [u8; 32], perm: [u8; 32], msg: [u8; 32], sigs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&addr);
    out.extend_from_slice(&perm);
    out.extend_from_slice(&msg);
    out.extend_from_slice(&word_u64(0x80));
    out.extend_from_slice(&abi_bytes_array(sigs));
    out
}

fn set_word(input: &mut [u8], word_idx: usize, w: [u8; 32]) {
    input[word_idx * 32..(word_idx + 1) * 32].copy_from_slice(&w);
}

/// The multi-sign message hash a signer must sign.
fn multi_hash(addr21: &[u8; 21], perm_id: i32, msg: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(57);
    preimage.extend_from_slice(addr21);
    preimage.extend_from_slice(&perm_id.to_be_bytes());
    preimage.extend_from_slice(msg);
    sha256(&preimage)
}

fn permission(id: i32, threshold: i64, keys: &[([u8; 21], i64)]) -> Permission {
    Permission {
        r#type: if id == 0 { 0 } else { 2 },
        id,
        permission_name: String::new(),
        threshold,
        parent_id: 0,
        operations: vec![],
        keys: keys
            .iter()
            .map(|(a, w)| Key { address: a.to_vec(), weight: *w })
            .collect(),
    }
}

// =============================================================================
// Differential runners
// =============================================================================

fn check_batch(diffs: &mut Vec<String>, name: &str, input: &[u8], restriction: bool) {
    let ctx = Ctx::new(restriction, HashMap::new());
    let expect = ref_batch(input, restriction);
    match PrecompileImpl::BatchValidateSign.execute(input, &ctx) {
        Ok(bytes) if bytes == expect => {}
        Ok(bytes) => diffs.push(format!(
            "[batch/{name} r={restriction}] output: ours={} java={}",
            hex::encode(&bytes),
            hex::encode(&expect)
        )),
        Err(e) => diffs.push(format!(
            "[batch/{name} r={restriction}] ours errored ({e:?}) but java always returns a word \
             (expected {})",
            hex::encode(&expect)
        )),
    }
    let ours_energy = PrecompileImpl::BatchValidateSign.energy_cost(input);
    let expect_energy = ref_batch_energy(input.len());
    if i64::try_from(ours_energy).ok() != Some(expect_energy) {
        diffs.push(format!(
            "[batch/{name} r={restriction}] energy: ours={ours_energy} java={expect_energy} \
             (len={})",
            input.len()
        ));
    }
}

/// Divergences that are known, reported defects in `precompiles.rs` at the
/// time this test was written. They are asserted to occur in EXACTLY the
/// shape recorded here, so the test still fails the moment a defect changes
/// behavior — including when it is fixed, which is the signal to delete the
/// corresponding arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum KnownDefect {
    /// D1 — `select_permission` (precompiles.rs:1524-1539) omits java's
    /// `getPermissionById` default-owner-permission synthesis: for `id == 0`
    /// on an account with no explicit `owner_permission`, java
    /// (`AccountCapsule.java:1325-1331`) returns a synthetic single-key
    /// permission (the account's own address, weight 1, threshold 1) while
    /// ours returns `None` → false. Real mainnet accounts commonly have no
    /// stored `owner_permission`, so this is live.
    MissingDefaultPermission,
    /// D2 — `total_weight += weight` (precompiles.rs:1511) is a checked add:
    /// it panics on overflow in debug builds where java's `long` addition
    /// wraps silently.
    WeightOverflowPanic,
    /// D3 — `energy_cost` (precompiles.rs:277-285) clamps java's negative
    /// `getEnergyForData` to 0 for calldata under 32 bytes (java returns
    /// -1500). Benign: those inputs have zero words, so `words[0]` throws
    /// before `Program.callToPrecompiledAddress` reaches the refund that
    /// would consume the negative cost — both sides burn the frame's energy.
    NegativeEnergyClamped,
}

fn check_multi(
    diffs: &mut Vec<String>,
    seen: &mut Vec<KnownDefect>,
    name: &str,
    input: &[u8],
    restriction: bool,
    accounts: &HashMap<[u8; 21], Account>,
) {
    let ctx = Ctx::new(restriction, accounts.clone());
    if let Some(expect) = ref_multi(input, restriction, accounts, true) {
        // A panic in the precompile is itself a divergence — java cannot
        // panic; every path lands in a catch or escapes as a modeled throw.
        let ours = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            PrecompileImpl::ValidateMultiSign.execute(input, &ctx)
        }));
        match ours {
            Err(p) => {
                let msg = p
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| p.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "non-string panic".into());
                if msg.contains("attempt to add with overflow") {
                    seen.push(KnownDefect::WeightOverflowPanic);
                } else {
                    diffs.push(format!(
                        "[multi/{name} r={restriction}] ours PANICKED ({msg}); \
                         java returns {expect:?}"
                    ));
                }
            }
            Ok(ours) => {
                let agrees = match (&expect, &ours) {
                    (RefMulti::Out(want), Ok(got)) => got == want,
                    (RefMulti::Throw, Err(PrecompileError::UncaughtThrow)) => true,
                    _ => false,
                };
                if !agrees {
                    // Re-run the reference with java's default-permission
                    // synthesis disabled. If that reproduces our output
                    // exactly, the divergence IS D1 and nothing else.
                    let without_default = ref_multi(input, restriction, accounts, false);
                    let is_d1 = match (&without_default, &ours) {
                        (Some(RefMulti::Out(want)), Ok(got)) => got == want,
                        (Some(RefMulti::Throw), Err(PrecompileError::UncaughtThrow)) => true,
                        _ => false,
                    };
                    if is_d1 {
                        seen.push(KnownDefect::MissingDefaultPermission);
                    } else {
                        diffs.push(format!(
                            "[multi/{name} r={restriction}] ours={} java={}",
                            match &ours {
                                Ok(b) => format!("Out({})", hex::encode(b)),
                                Err(e) => format!("{e:?}"),
                            },
                            match &expect {
                                RefMulti::Out(b) => format!("Out({})", hex::encode(b)),
                                RefMulti::Throw => "UncaughtThrow".into(),
                            }
                        ));
                    }
                }
            }
        }
    }

    let ours_energy = PrecompileImpl::ValidateMultiSign.energy_cost(input);
    let expect_energy = ref_multi_energy(input.len());
    if i64::try_from(ours_energy).ok() != Some(expect_energy) {
        // The only tolerated shape is java's negative cost clamped to zero.
        if expect_energy < 0 && ours_energy == 0 {
            seen.push(KnownDefect::NegativeEnergyClamped);
            // ...and it is only benign because such inputs always throw.
            assert!(
                matches!(
                    ref_multi(input, restriction, accounts, true),
                    Some(RefMulti::Throw)
                ),
                "[multi/{name}] java's negative energy cost became observable: an input with \
                 cost {expect_energy} did NOT throw, so the refund path is reachable and the \
                 clamp in energy_cost is a real consensus divergence"
            );
        } else {
            diffs.push(format!(
                "[multi/{name} r={restriction}] energy: ours={ours_energy} java={expect_energy} \
                 (len={})",
                input.len()
            ));
        }
    }
}

/// Fail with every collected divergence (deduplicated, first 80 shown).
fn report(diffs: Vec<String>) {
    if diffs.is_empty() {
        return;
    }
    let mut unique: Vec<String> = Vec::new();
    for d in diffs {
        if !unique.contains(&d) {
            unique.push(d);
        }
    }
    let shown = unique.len().min(80);
    panic!(
        "{} divergence(s) vs the java-derived reference (showing {shown}):\n{}",
        unique.len(),
        unique[..shown].join("\n")
    );
}

/// Truncation + garbage-append sweep shared by both precompiles.
fn length_sweep(input: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut cuts: Vec<usize> = vec![0, 1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128];
    if input.len() > 1 {
        cuts.extend([input.len() - 1, input.len() - 33.min(input.len() - 1), input.len() / 2]);
    }
    for c in cuts {
        if c <= input.len() {
            out.push((format!("cut@{c}"), input[..c].to_vec()));
        }
    }
    for extra in [1usize, 31, 32, 33, 64] {
        let mut v = input.to_vec();
        v.extend(std::iter::repeat_n(0xEEu8, extra));
        out.push((format!("append{extra}"), v));
    }
    out
}

const BOTH_ERAS: [bool; 2] = [false, true];

// =============================================================================
// Sanity anchors for the reference itself (so agreement is not vacuous)
// =============================================================================

#[test]
fn reference_semantics_anchor() {
    let hash = [0xABu8; 32];
    let keys: Vec<SigningKey> = (1..=3).map(sk).collect();
    let sigs: Vec<Vec<u8>> = keys.iter().map(|k| sign65(k, &hash)).collect();
    let addrs: Vec<[u8; 32]> = keys.iter().map(|k| addr_word(&addr_of(k))).collect();
    let input = batch_input(&hash, &sigs, &addrs);
    for era in BOTH_ERAS {
        let out = ref_batch(&input, era);
        assert_eq!(&out[..3], &[1, 1, 1], "reference must validate well-formed batch input");
        // High-s forms must also validate — the bug class under test.
        let hs: Vec<Vec<u8>> = sigs.iter().map(|s| flip_s(s)).collect();
        let hs_input = batch_input(&hash, &hs, &addrs);
        assert_eq!(&ref_batch(&hs_input, era)[..3], &[1, 1, 1], "high-s must recover");
    }

    // Multi: default owner permission, threshold 1.
    let owner = sk(7);
    let owner_addr = addr_of(&owner);
    let msg = [0x11u8; 32];
    let h = multi_hash(&owner_addr, 0, &msg);
    let account = Account { address: owner_addr.to_vec(), ..Default::default() };
    let accounts = HashMap::from([(owner_addr, account)]);
    let input = multi_input(addr_word(&owner_addr), word_u64(0), msg, &[sign65(&owner, &h)]);
    for era in BOTH_ERAS {
        assert_eq!(
            ref_multi(&input, era, &accounts, true),
            Some(RefMulti::Out(data_true())),
            "reference must validate a well-formed owner multisig"
        );
    }
}

// =============================================================================
// BatchValidateSign differential
// =============================================================================

#[test]
fn batch_validate_sign_differential() {
    let hash = [0xABu8; 32];
    let keys: Vec<SigningKey> = (1..=16).map(sk).collect();
    let all_sigs: Vec<Vec<u8>> = keys.iter().map(|k| sign65(k, &hash)).collect();
    let all_addrs: Vec<[u8; 32]> = keys.iter().map(|k| addr_word(&addr_of(k))).collect();

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();

    // Well-formed, several sizes.
    for n in [1usize, 2, 3, 5, 16] {
        cases.push((
            format!("ok{n}"),
            batch_input(&hash, &all_sigs[..n].to_vec(), &all_addrs[..n]),
        ));
    }
    // One wrong address among three.
    {
        let mut addrs = all_addrs[..3].to_vec();
        addrs[1] = all_addrs[7];
        cases.push(("wrong_addr_mid".into(), batch_input(&hash, &all_sigs[..3].to_vec(), &addrs)));
    }
    // High-s forms.
    {
        let hs: Vec<Vec<u8>> = all_sigs[..3].iter().map(|s| flip_s(s)).collect();
        cases.push(("high_s".into(), batch_input(&hash, &hs, &all_addrs[..3])));
    }
    // Dirty upper 12 bytes of an address word — java compares last 20 only.
    {
        let mut addrs = all_addrs[..2].to_vec();
        addrs[0][..12].copy_from_slice(&[0xFF; 12]);
        cases.push(("dirty_addr_high".into(), batch_input(&hash, &all_sigs[..2].to_vec(), &addrs)));
    }
    // Duplicate signature + duplicate address (no dedup in batch).
    {
        let sigs = vec![all_sigs[0].clone(), all_sigs[0].clone()];
        let addrs = [all_addrs[0], all_addrs[0]];
        cases.push(("dup_pairs".into(), batch_input(&hash, &sigs, &addrs)));
    }
    // v sweep on the middle of three signatures.
    for v in [0u8, 1, 2, 26, 27, 28, 29, 31, 100, 255] {
        let mut sigs = all_sigs[..3].to_vec();
        sigs[1][64] = v;
        cases.push((format!("v={v}"), batch_input(&hash, &sigs, &all_addrs[..3])));
    }
    // r/s edge values on a single-signature input.
    let one = || (all_sigs[..1].to_vec(), all_addrs[..1].to_vec());
    let half_n_plus_1: [u8; 32] =
        hex_literal::hex!("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");
    let n_minus_1 = {
        let mut b = N_BYTES;
        b[31] -= 1;
        b
    };
    let n_plus_1 = {
        let mut b = N_BYTES;
        b[31] += 1;
        b
    };
    for (fname, off) in [("r", 0usize), ("s", 32usize)] {
        for (vname, val) in [
            ("zero", [0u8; 32]),
            ("one", word_u64(1)),
            ("half_n", HALF_N_BYTES),
            ("half_n+1", half_n_plus_1),
            ("n-1", n_minus_1),
            ("n", N_BYTES),
            ("n+1", n_plus_1),
        ] {
            let (mut sigs, addrs) = one();
            sigs[0][off..off + 32].copy_from_slice(&val);
            cases.push((format!("{fname}={vname}"), batch_input(&hash, &sigs, &addrs)));
        }
    }
    // Garbage signature bytes.
    {
        let (mut sigs, addrs) = one();
        sigs[0] = vec![0x5A; 65];
        cases.push(("garbage_sig".into(), batch_input(&hash, &sigs, &addrs)));
    }
    // Count edges: empty arrays, over-cap, mismatched counts.
    cases.push(("empty_both".into(), batch_input(&hash, &[], &[])));
    {
        let sigs: Vec<Vec<u8>> = (0..17).map(|i| all_sigs[i % 16].clone()).collect();
        let addrs: Vec<[u8; 32]> = (0..17).map(|i| all_addrs[i % 16]).collect();
        cases.push(("seventeen".into(), batch_input(&hash, &sigs, &addrs)));
    }
    cases.push((
        "count_mismatch".into(),
        batch_input(&hash, &all_sigs[..2].to_vec(), &all_addrs[..3]),
    ));
    // Declared count larger / smaller than actual elements.
    {
        let mut input = batch_input(&hash, &all_sigs[..2].to_vec(), &all_addrs[..2]);
        set_word(&mut input, 3, word_u64(5)); // sig array count word
        cases.push(("sig_count_raised".into(), input));
        let mut input = batch_input(&hash, &all_sigs[..2].to_vec(), &all_addrs[..2]);
        set_word(&mut input, 3, word_u64(1));
        cases.push(("sig_count_lowered".into(), input));
        let mut input = batch_input(&hash, &all_sigs[..2].to_vec(), &all_addrs[..2]);
        let addr_count_word = input.len() / 32 - 3;
        set_word(&mut input, addr_count_word, word_u64(1000));
        cases.push(("addr_count_huge".into(), input));
    }
    // Head-offset games.
    {
        let base = batch_input(&hash, &all_sigs[..2].to_vec(), &all_addrs[..2]);
        for (nm, w1) in [
            ("sig_off_zero", word_u64(0)),
            ("sig_off_unaligned", word_u64(0x61)),
            ("sig_off_points_at_addrs", word_u64(0x60 + 32 * 9)),
            ("sig_off_end", word_u64(base.len() as u64)),
            ("sig_off_oob", word_u64(base.len() as u64 + 320)),
            ("sig_off_max", [0xFF; 32]),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 1, w1);
            cases.push((nm.into(), input));
        }
        for (nm, w2) in [
            ("addr_off_zero", word_u64(0)),
            ("addr_off_sig", word_u64(0x60)),
            ("addr_off_oob", word_u64(base.len() as u64 + 32)),
            ("addr_off_max", [0xFF; 32]),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 2, w2);
            cases.push((nm.into(), input));
        }
        // Element relative-offset games (word 4 = first element offset).
        for (nm, w4) in [
            ("elem_off_zero", word_u64(0)),
            ("elem_off_unaligned", word_u64(0x41)),
            ("elem_off_oob", word_u64(4096)),
            ("elem_off_max", [0xFF; 32]),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 4, w4);
            cases.push((nm.into(), input));
        }
        // Element length-word games (word 6 = first element's length word).
        for (nm, len) in [
            ("elem_len_0", 0u64),
            ("elem_len_64", 64),
            ("elem_len_66", 66),
            ("elem_len_1000", 1000),
            ("elem_len_100000", 100_000),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 6, word_u64(len));
            cases.push((nm.into(), input));
        }
    }
    // Bare-minimum inputs.
    for n in [1usize, 2, 3, 4] {
        cases.push((format!("bare{}w", n), vec![0x11; 32 * n]));
    }

    let mut diffs = Vec::new();
    for (name, input) in &cases {
        for era in BOTH_ERAS {
            check_batch(&mut diffs, name, input, era);
            for (sub, mutated) in length_sweep(input) {
                check_batch(&mut diffs, &format!("{name}/{sub}"), &mutated, era);
            }
        }
    }
    report(diffs);
}

// =============================================================================
// ValidateMultiSign differential
// =============================================================================

#[test]
fn validate_multi_sign_differential() {
    let owner = sk(21);
    let k2 = sk(22);
    let k3 = sk(23);
    let stranger = sk(99);
    let owner_addr = addr_of(&owner);
    let msg = [0x11u8; 32];

    // Accounts fixture:
    //  A: bare account (default owner permission from stored address).
    //  B: explicit owner permission, 2 keys weight 1, threshold 2;
    //     active permission id=2 (owner+k3, threshold 1); witness id=1 (k2).
    //  C: stored address DIFFERS from lookup key (default-permission edge).
    //  D: key stored as 20 bytes (no 0x41 prefix) — never matches.
    //  E: threshold 0.
    //  F: weights near i64::MAX (overflow wrap check).
    //  G: explicit 1-of-1 owner permission (unmasked structural base).
    let b_addr = addr_of(&sk(31));
    let c_addr = addr_of(&sk(32));
    let d_addr = addr_of(&sk(33));
    let e_addr = addr_of(&sk(34));
    let f_addr = addr_of(&sk(35));
    let g_addr = addr_of(&sk(36));
    let mut b_account = Account { address: b_addr.to_vec(), ..Default::default() };
    b_account.owner_permission =
        Some(permission(0, 2, &[(addr_of(&owner), 1), (addr_of(&k2), 1)]));
    b_account.witness_permission = Some(permission(1, 1, &[(addr_of(&k2), 1)]));
    b_account.active_permission =
        vec![permission(2, 1, &[(addr_of(&owner), 1), (addr_of(&k3), 1)])];
    let c_account = Account { address: owner_addr.to_vec(), ..Default::default() };
    let mut d_account = Account { address: d_addr.to_vec(), ..Default::default() };
    d_account.owner_permission = Some(Permission {
        keys: vec![Key { address: addr_of(&owner)[1..].to_vec(), weight: 1 }],
        threshold: 1,
        ..permission(0, 1, &[])
    });
    let mut e_account = Account { address: e_addr.to_vec(), ..Default::default() };
    e_account.owner_permission = Some(permission(0, 0, &[(addr_of(&owner), 1)]));
    let mut f_account = Account { address: f_addr.to_vec(), ..Default::default() };
    f_account.owner_permission = Some(permission(
        0,
        3,
        &[(addr_of(&owner), i64::MAX), (addr_of(&k2), i64::MAX)],
    ));
    let mut g_account = Account { address: g_addr.to_vec(), ..Default::default() };
    g_account.owner_permission = Some(permission(0, 1, &[(addr_of(&owner), 1)]));
    let accounts = HashMap::from([
        (owner_addr, Account { address: owner_addr.to_vec(), ..Default::default() }),
        (b_addr, b_account),
        (c_addr, c_account),
        (d_addr, d_account),
        (e_addr, e_account),
        (f_addr, f_account),
        (g_addr, g_account),
    ]);

    let h_a0 = multi_hash(&owner_addr, 0, &msg);
    let h_b0 = multi_hash(&b_addr, 0, &msg);
    let h_b1 = multi_hash(&b_addr, 1, &msg);
    let h_b2 = multi_hash(&b_addr, 2, &msg);

    let mut cases: Vec<(String, Vec<u8>)> = Vec::new();

    // Well-formed: default owner permission, threshold 1.
    cases.push((
        "owner_default_ok".into(),
        multi_input(addr_word(&owner_addr), word_u64(0), msg, &[sign65(&owner, &h_a0)]),
    ));
    // High-s form of the same — the bug class.
    cases.push((
        "owner_default_high_s".into(),
        multi_input(addr_word(&owner_addr), word_u64(0), msg, &[flip_s(&sign65(&owner, &h_a0))]),
    ));
    // Explicit 2-of-2: both sign / only one signs.
    cases.push((
        "b_owner_2of2_ok".into(),
        multi_input(
            addr_word(&b_addr),
            word_u64(0),
            msg,
            &[sign65(&owner, &h_b0), sign65(&k2, &h_b0)],
        ),
    ));
    cases.push((
        "b_owner_2of2_partial".into(),
        multi_input(addr_word(&b_addr), word_u64(0), msg, &[sign65(&owner, &h_b0)]),
    ));
    // Witness (id 1) and active (id 2) permissions; unknown id 5.
    cases.push((
        "b_witness_ok".into(),
        multi_input(addr_word(&b_addr), word_u64(1), msg, &[sign65(&k2, &h_b1)]),
    ));
    cases.push((
        "b_active_ok".into(),
        multi_input(addr_word(&b_addr), word_u64(2), msg, &[sign65(&k3, &h_b2)]),
    ));
    cases.push((
        "b_unknown_perm".into(),
        multi_input(addr_word(&b_addr), word_u64(5), msg, &[sign65(&owner, &h_b0)]),
    ));
    // Permission-id word with dirty high bytes → intValueSafe clamps to MAX.
    {
        let mut perm = word_u64(0);
        perm[0] = 1;
        cases.push((
            "perm_id_dirty_high".into(),
            multi_input(addr_word(&b_addr), perm, msg, &[sign65(&owner, &h_b0)]),
        ));
    }
    // Exact duplicate (addr, sig) skipped: same sig twice on a 2-threshold
    // permission stays below threshold; on the 1-threshold default it passes.
    cases.push((
        "b_exact_dup_below_threshold".into(),
        multi_input(
            addr_word(&b_addr),
            word_u64(0),
            msg,
            &[sign65(&owner, &h_b0), sign65(&owner, &h_b0)],
        ),
    ));
    cases.push((
        "owner_exact_dup_ok".into(),
        multi_input(
            addr_word(&owner_addr),
            word_u64(0),
            msg,
            &[sign65(&owner, &h_a0), sign65(&owner, &h_a0)],
        ),
    ));
    // The double-count quirk: one key, two DIFFERENT signature encodings
    // (low-s and high-s) — java counts the weight twice, meeting a
    // 2-threshold with a single key.
    {
        let low = sign65(&owner, &h_b0);
        let high = flip_s(&low);
        cases.push((
            "b_double_count_quirk".into(),
            multi_input(addr_word(&b_addr), word_u64(0), msg, &[low, high]),
        ));
    }
    // Unknown signer (valid signature, weight 0) → immediate FALSE.
    cases.push((
        "b_stranger".into(),
        multi_input(
            addr_word(&b_addr),
            word_u64(0),
            msg,
            &[sign65(&stranger, &h_b0), sign65(&owner, &h_b0)],
        ),
    ));
    // Invalid signature (bad v) → recovery null → java NPE → FALSE.
    {
        let mut bad = sign65(&owner, &h_a0);
        bad[64] = 29;
        cases.push((
            "owner_bad_v".into(),
            multi_input(addr_word(&owner_addr), word_u64(0), msg, &[bad]),
        ));
    }
    // s = n (invalid) and s high (valid) on the A account.
    {
        let mut bad = sign65(&owner, &h_a0);
        bad[32..64].copy_from_slice(&N_BYTES);
        cases.push((
            "owner_s_eq_n".into(),
            multi_input(addr_word(&owner_addr), word_u64(0), msg, &[bad]),
        ));
    }
    // Account missing entirely.
    cases.push((
        "no_account".into(),
        multi_input(addr_word(&addr_of(&sk(77))), word_u64(0), msg, &[sign65(&owner, &h_a0)]),
    ));
    // Stored address differs from lookup key: java's default permission
    // uses the STORED bytes, so the owner of the stored address validates.
    {
        let h_c = multi_hash(&c_addr, 0, &msg);
        cases.push((
            "c_stored_addr_mismatch".into(),
            multi_input(addr_word(&c_addr), word_u64(0), msg, &[sign65(&owner, &h_c)]),
        ));
    }
    // 20-byte stored key never matches a 21-byte recovered address.
    {
        let h_d = multi_hash(&d_addr, 0, &msg);
        cases.push((
            "d_20byte_key".into(),
            multi_input(addr_word(&d_addr), word_u64(0), msg, &[sign65(&owner, &h_d)]),
        ));
    }
    // Threshold 0: any single weighted signature passes (0 >= 0 is true
    // even before, but signatures.length == 0 is rejected first).
    {
        let h_e = multi_hash(&e_addr, 0, &msg);
        cases.push((
            "e_threshold_zero".into(),
            multi_input(addr_word(&e_addr), word_u64(0), msg, &[sign65(&owner, &h_e)]),
        ));
    }
    // Weight overflow wraps (java long addition): MAX + MAX < 3.
    {
        let h_f = multi_hash(&f_addr, 0, &msg);
        cases.push((
            "f_weight_overflow".into(),
            multi_input(
                addr_word(&f_addr),
                word_u64(0),
                msg,
                &[sign65(&owner, &h_f), sign65(&k2, &h_f)],
            ),
        ));
    }
    // Signature-count edges: empty, five, six.
    cases.push((
        "empty_sigs".into(),
        multi_input(addr_word(&owner_addr), word_u64(0), msg, &[]),
    ));
    {
        let five: Vec<Vec<u8>> = (0..5).map(|_| sign65(&owner, &h_a0)).collect();
        cases.push((
            "five_sigs".into(),
            multi_input(addr_word(&owner_addr), word_u64(0), msg, &five),
        ));
        let six: Vec<Vec<u8>> = (0..6).map(|_| sign65(&owner, &h_a0)).collect();
        cases.push((
            "six_sigs".into(),
            multi_input(addr_word(&owner_addr), word_u64(0), msg, &six),
        ));
    }
    // Explicit-permission twins of the well-formed cases, so the structural
    // mutations below are not masked by any divergence on the
    // default-permission path (account G has an explicit 1-of-1 owner
    // permission and behaves identically to A in java).
    let h_g = multi_hash(&g_addr, 0, &msg);
    cases.push((
        "g_explicit_ok".into(),
        multi_input(addr_word(&g_addr), word_u64(0), msg, &[sign65(&owner, &h_g)]),
    ));
    cases.push((
        "g_explicit_high_s".into(),
        multi_input(addr_word(&g_addr), word_u64(0), msg, &[flip_s(&sign65(&owner, &h_g))]),
    ));
    {
        let five: Vec<Vec<u8>> = (0..5).map(|_| sign65(&owner, &h_g)).collect();
        cases.push((
            "g_five_sigs".into(),
            multi_input(addr_word(&g_addr), word_u64(0), msg, &five),
        ));
    }
    // Head-offset games — the era-split throw-vs-false edge lives here.
    {
        let base = multi_input(addr_word(&g_addr), word_u64(0), msg, &[sign65(&owner, &h_g)]);
        for (nm, w3) in [
            ("sig_off_zero", word_u64(0)),
            ("sig_off_unaligned", word_u64(0x81)),
            ("sig_off_end", word_u64(base.len() as u64)),
            ("sig_off_oob", word_u64(base.len() as u64 + 320)),
            ("sig_off_max", [0xFF; 32]),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 3, w3);
            cases.push((nm.into(), input));
        }
        // Element relative-offset games (word 5 = first element offset).
        for (nm, w5) in [
            ("elem_off_zero", word_u64(0)),
            ("elem_off_unaligned", word_u64(0x21)),
            ("elem_off_oob", word_u64(4096)),
            ("elem_off_max", [0xFF; 32]),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 5, w5);
            cases.push((nm.into(), input));
        }
        // Element length-word games (word 6): post-#94 ignores it entirely,
        // pre-#94 obeys the declared length.
        for (nm, len) in [
            ("elem_len_0", 0u64),
            ("elem_len_64", 64),
            ("elem_len_66", 66),
            ("elem_len_1000", 1000),
            ("elem_len_100000", 100_000),
        ] {
            let mut input = base.clone();
            set_word(&mut input, 6, word_u64(len));
            cases.push((nm.into(), input));
        }
        // Declared sig count raised/lowered (word 4).
        for (nm, cnt) in [("sig_count_raised", 4u64), ("sig_count_lowered", 0)] {
            let mut input = base.clone();
            set_word(&mut input, 4, word_u64(cnt));
            cases.push((nm.into(), input));
        }
    }
    // Bare-minimum inputs (uncaught-throw territory: fewer than 4 words).
    for n in [1usize, 2, 3, 4] {
        cases.push((format!("bare{}w", n), vec![0x11; 32 * n]));
    }

    // D2 makes the precompile panic by design; `check_unwind` in
    // `check_multi` classifies it, so the default hook's backtrace spam is
    // suppressed for the duration of the sweep.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|info| {
        let msg = info.to_string();
        if !msg.contains("attempt to add with overflow") {
            eprintln!("{msg}");
        }
    }));

    let mut diffs = Vec::new();
    let mut seen = Vec::new();
    for (name, input) in &cases {
        for era in BOTH_ERAS {
            check_multi(&mut diffs, &mut seen, name, input, era, &accounts);
            for (sub, mutated) in length_sweep(input) {
                check_multi(
                    &mut diffs,
                    &mut seen,
                    &format!("{name}/{sub}"),
                    &mutated,
                    era,
                    &accounts,
                );
            }
        }
    }
    std::panic::set_hook(default_hook);
    report(diffs);

    // Every known defect must still be exercised by the corpus. If one stops
    // appearing it has been fixed (delete its `KnownDefect` arm and the
    // tolerance in `check_multi`) or the corpus stopped covering it — either
    // way this test must not keep silently tolerating it.
    seen.sort();
    seen.dedup();
    let expected = vec![
        KnownDefect::MissingDefaultPermission,
        KnownDefect::WeightOverflowPanic,
        KnownDefect::NegativeEnergyClamped,
    ];
    assert_eq!(
        seen, expected,
        "the set of tolerated known defects changed; see the KnownDefect docs — a defect that \
         disappeared is fixed and its tolerance must be removed"
    );
}
