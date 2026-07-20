//! Differential check of our local ECRecover against the upstream revm
//! precompile. The only permitted difference is TRON's 21-byte address form:
//! java builds the result with `Hash.sha3omit12`, so the output word carries
//! the prefix byte at index 11 where Ethereum's carries a twelfth zero.
//!
//! Anything else differing is a consensus bug. High-s signatures are the case
//! that matters most: java bounds `s` only by the group order, so it recovers
//! from them, and rejecting them silently breaks every signature-checking
//! contract on the chain.
use revm::precompile::secp256k1::ec_recover_run;
use tron_tvm::{EvmContext, EvmContextError, PrecompileImpl};

#[derive(Default)]
struct Ctx;
impl EvmContext for Ctx {
    fn caller(&self) -> tron_crypto::address::Address { tron_crypto::address::Address::from_raw([0u8;21]) }
    fn callee(&self) -> tron_crypto::address::Address { tron_crypto::address::Address::from_raw([0u8;21]) }
    fn get_account(&self, _: &tron_crypto::address::Address) -> Result<Option<tron_proto::Account>, EvmContextError> { Ok(None) }
    fn get_witness(&self, _: &tron_crypto::address::Address) -> Result<Option<tron_proto::Witness>, EvmContextError> { Ok(None) }
    fn chain_parameter_long(&self, _: &[u8]) -> Result<Option<i64>, EvmContextError> { Ok(None) }
    fn block_number(&self) -> i64 { 0 }
    fn block_timestamp_ms(&self) -> i64 { 0 }
    fn all_witnesses(&self) -> Result<Vec<tron_proto::Witness>, EvmContextError> { Ok(vec![]) }
    fn get_delegated_resource(&self, _: &tron_crypto::address::Address, _: &tron_crypto::address::Address) -> Result<Option<tron_proto::DelegatedResource>, EvmContextError> { Ok(None) }
    fn dynamic_energy_factor(&self, _: &tron_crypto::address::Address) -> Result<i64, EvmContextError> { Ok(0) }
}

fn ours(input: &[u8]) -> Vec<u8> {
    PrecompileImpl::EcRecover.execute(input, &Ctx).unwrap_or_default()
}
fn theirs(input: &[u8]) -> Vec<u8> {
    ec_recover_run(input, 1_000_000).map(|o| o.bytes.to_vec()).unwrap_or_default()
}

#[test]
fn matches_upstream_except_for_the_tron_address_prefix() {
    // A known-good vector, then systematic mutations of each field.
    let base = hex::decode(concat!(
        "456e9aea5e197a1f1af7a3e85a3212fa4049a3ba34c2289b4c860fc0b0c64ef3",
        "000000000000000000000000000000000000000000000000000000000000001c",
        "9242685bf161793cc25603c231bc2f568eb630ea16aa137d2664ac8038825608",
        "4f8ae3bd7535248d0bd448298cc2e2071e56992d0774dc340c368ae950852ada"
    )).unwrap();

    let mut cases: Vec<(String, Vec<u8>)> = vec![("canonical".into(), base.clone())];
    // truncations
    for len in [0usize, 31, 64, 95, 96, 100, 127] {
        cases.push((format!("len={len}"), base[..len].to_vec()));
    }
    // v variants
    for v in [0u8, 1, 26, 27, 28, 29, 31, 255] {
        let mut c = base.clone(); c[63] = v; cases.push((format!("v={v}"), c));
    }
    // dirty high bytes of the v word
    let mut c = base.clone(); c[32] = 1; cases.push(("v_word_dirty".into(), c));
    // r/s edge values
    let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    for (name, off) in [("r", 64usize), ("s", 96usize)] {
        let mut z = base.clone(); z[off..off+32].fill(0); cases.push((format!("{name}=0"), z));
        let mut eq = base.clone(); eq[off..off+32].copy_from_slice(&n); cases.push((format!("{name}=N"), eq));
        let mut gt = base.clone(); gt[off..off+32].copy_from_slice(&n); gt[off+31] = 0x42; cases.push((format!("{name}=N+1"), gt));
        let mut hi = base.clone(); hi[off] = 0xff; cases.push((format!("{name}_high_bit"), hi));
    }
    // high-s (s > n/2) — valid ECDSA, rejected by some backends
    let half_n_plus = hex::decode("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1").unwrap();
    let mut hs = base.clone(); hs[96..128].copy_from_slice(&half_n_plus); cases.push(("s_just_above_half_n".into(), hs));

    for (name, input) in &cases {
        let (a, b) = (ours(input), theirs(input));
        assert_eq!(
            a.len(), b.len(),
            "[{name}] one side recovered and the other did not: ours={} theirs={}",
            hex::encode(&a), hex::encode(&b)
        );
        if a.is_empty() {
            continue;
        }
        assert_eq!(a[11], 0x41, "[{name}] missing the TRON prefix byte");
        assert_eq!(&a[12..], &b[12..], "[{name}] recovered a different address");
        assert_eq!(&a[..11], &b[..11], "[{name}] leading bytes differ");
    }
}
