//! Osaka-gated precompile behaviour: TIP-7823 / TIP-7883 / TIP-871 for
//! MODEXP, TIP-854 calldata canonicalisation for the signature precompiles,
//! and the java-tron P256VERIFY conformance vectors.

use tron_crypto::address::Address;
use tron_proto::{Account, DelegatedResource, Witness};
use tron_tvm::{EvmContext, EvmContextError, PrecompileError, PrecompileImpl};

struct Ctx {
    osaka: bool,
}

impl EvmContext for Ctx {
    fn caller(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn callee(&self) -> Address {
        Address::from_raw([0u8; 21])
    }
    fn get_account(&self, _: &Address) -> Result<Option<Account>, EvmContextError> {
        Ok(None)
    }
    fn get_witness(&self, _: &Address) -> Result<Option<Witness>, EvmContextError> {
        Ok(None)
    }
    fn chain_parameter_long(&self, key: &[u8]) -> Result<Option<i64>, EvmContextError> {
        Ok(match key {
            b"ALLOW_TVM_OSAKA" => Some(self.osaka as i64),
            b"ALLOW_TVM_SELFDESTRUCT_RESTRICTION" => Some(1),
            _ => None,
        })
    }
    fn block_number(&self) -> i64 {
        0
    }
    fn block_timestamp_ms(&self) -> i64 {
        0
    }
    fn all_witnesses(&self) -> Result<Vec<Witness>, EvmContextError> {
        Ok(Vec::new())
    }
    fn get_delegated_resource(
        &self,
        _: &Address,
        _: &Address,
    ) -> Result<Option<DelegatedResource>, EvmContextError> {
        Ok(None)
    }
    fn dynamic_energy_factor(&self, _: &Address) -> Result<i64, EvmContextError> {
        Ok(0)
    }
}

const OSAKA: Ctx = Ctx { osaka: true };
const LEGACY: Ctx = Ctx { osaka: false };

fn len_word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[28..].copy_from_slice(&(n as u32).to_be_bytes());
    w
}

/// java `AllowTvmOsakaTest.buildModExpData`: three length words, a zero
/// base, `exp_value` left-aligned in a zero exponent, and a zero modulus.
fn modexp_data(base_len: usize, exp_len: usize, mod_len: usize, exp_value: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&len_word(base_len));
    data.extend_from_slice(&len_word(exp_len));
    data.extend_from_slice(&len_word(mod_len));
    data.extend(std::iter::repeat_n(0u8, base_len));
    let mut exp = vec![0u8; exp_len];
    let n = exp_value.len().min(exp_len);
    exp[..n].copy_from_slice(&exp_value[..n]);
    data.extend(exp);
    data.extend(std::iter::repeat_n(0u8, mod_len));
    data
}

fn modexp_energy(ctx: &Ctx, base_len: usize, exp_len: usize, mod_len: usize, exp: &[u8]) -> u64 {
    PrecompileImpl::ModExp
        .effective_energy_cost(&modexp_data(base_len, exp_len, mod_len, exp), ctx)
        .unwrap()
}

#[test]
fn tip7883_modexp_pricing_matches_java_vectors() {
    let square = [0x02];
    let qube = [0x03];
    let pow_0x10001 = [0x01, 0x00, 0x01];
    let e = |b, x, m, v: &[u8]| modexp_energy(&OSAKA, b, x, m, v);

    assert_eq!(e(64, 1, 64, &square), 500);
    assert_eq!(e(64, 1, 64, &qube), 500);
    assert_eq!(e(64, 3, 64, &pow_0x10001), 2048);

    assert_eq!(e(128, 1, 128, &square), 512);
    assert_eq!(e(128, 1, 128, &qube), 512);
    assert_eq!(e(128, 3, 128, &pow_0x10001), 8192);

    assert_eq!(e(256, 1, 256, &square), 2048);
    assert_eq!(e(256, 1, 256, &qube), 2048);
    assert_eq!(e(256, 3, 256, &pow_0x10001), 32768);

    assert_eq!(e(512, 1, 512, &square), 8192);
    assert_eq!(e(512, 1, 512, &qube), 8192);
    assert_eq!(e(512, 3, 512, &pow_0x10001), 131072);

    assert_eq!(e(1024, 1, 1024, &square), 32768);
    assert_eq!(e(1024, 1, 1024, &qube), 32768);
    assert_eq!(e(1024, 3, 1024, &pow_0x10001), 524288);

    assert_eq!(e(0, 0, 0, &[]), 500);
    assert_eq!(e(1, 1, 1, &square), 500);
    assert_eq!(e(32, 1, 32, &square), 500);
    assert_eq!(e(33, 1, 33, &square), 500);
    assert_eq!(e(33, 64, 33, &[]), 25600);
    assert_eq!(e(64, 64, 64, &[]), 65536);
    assert_eq!(e(64, 64, 64, &[0x01]), 97280);
}

#[test]
fn tip7883_only_applies_under_osaka() {
    assert_eq!(modexp_energy(&LEGACY, 64, 1, 64, &[0x02]), 204);
    assert_eq!(modexp_energy(&LEGACY, 128, 1, 128, &[0x02]), 665);
    assert_eq!(modexp_energy(&OSAKA, 128, 1, 128, &[0x02]), 512);
}

#[test]
fn tip7823_rejects_lengths_over_1024_under_osaka() {
    let exec = |ctx: &Ctx, b, x, m| PrecompileImpl::ModExp.execute(&modexp_data(b, x, m, &[]), ctx);

    assert!(exec(&OSAKA, 1024, 0, 0).is_ok());
    for (b, x, m) in [(1025, 0, 0), (0, 1025, 0), (0, 0, 1025)] {
        assert!(
            matches!(exec(&OSAKA, b, x, m), Err(PrecompileError::SpendAllRevert)),
            "({b}, {x}, {m}) must fail under Osaka"
        );
        assert!(exec(&LEGACY, b, x, m).is_ok(), "({b}, {x}, {m}) must pass pre-Osaka");
    }
}

#[test]
fn tip871_zero_modulus_returns_mod_len_zero_bytes_under_osaka() {
    let data = modexp_data(1, 1, 4, &[0x02]);
    assert_eq!(PrecompileImpl::ModExp.execute(&data, &OSAKA).unwrap(), vec![0u8; 4]);
    assert_eq!(PrecompileImpl::ModExp.execute(&data, &LEGACY).unwrap(), Vec::<u8>::new());
    // modLen == 0 stays empty either way.
    let data = modexp_data(1, 1, 0, &[0x02]);
    assert_eq!(PrecompileImpl::ModExp.execute(&data, &OSAKA).unwrap(), Vec::<u8>::new());
}

#[test]
fn modexp_output_is_unchanged_by_osaka_for_a_nonzero_modulus() {
    // 3^7 mod 10 = 7, left-padded to modLen.
    let mut data = Vec::new();
    data.extend_from_slice(&len_word(1));
    data.extend_from_slice(&len_word(1));
    data.extend_from_slice(&len_word(2));
    data.extend_from_slice(&[3, 7, 0, 10]);
    assert_eq!(PrecompileImpl::ModExp.execute(&data, &OSAKA).unwrap(), vec![0, 7]);
    assert_eq!(PrecompileImpl::ModExp.execute(&data, &LEGACY).unwrap(), vec![0, 7]);
}

fn is_spend_all(result: &Result<Vec<u8>, PrecompileError>) -> bool {
    matches!(result, Err(PrecompileError::SpendAllRevert))
}

#[test]
fn tip854_rejects_non_canonical_calldata_under_osaka() {
    // (precompile, header words, item words)
    let cases = [
        (PrecompileImpl::BatchValidateSign, 5, 6),
        (PrecompileImpl::ValidateMultiSign, 5, 5),
    ];
    for (pre, header, item) in cases {
        let canonical = (header + item) * 32;
        // Not a whole number of words.
        for len in [1usize, 31, 33, canonical - 1, canonical + 1] {
            let data = vec![0u8; len];
            assert!(is_spend_all(&pre.execute(&data, &OSAKA)), "{pre:?} len={len}");
        }
        // Whole words, but no items or a partial item.
        for words in [0usize, header, header + 1, header + item - 1, header + item + 1] {
            let data = vec![0u8; words * 32];
            assert!(is_spend_all(&pre.execute(&data, &OSAKA)), "{pre:?} words={words}");
            assert!(!is_spend_all(&pre.execute(&data, &LEGACY)), "{pre:?} words={words} pre-Osaka");
        }
        // Canonical lengths behave exactly as before.
        for items in 1..=3 {
            let data = vec![0u8; (header + item * items) * 32];
            let before = pre.execute(&data, &LEGACY);
            let after = pre.execute(&data, &OSAKA);
            assert!(!is_spend_all(&after), "{pre:?} items={items}");
            assert_eq!(format!("{before:?}"), format!("{after:?}"), "{pre:?} items={items}");
        }
    }
}

#[test]
fn p256_verify_passes_java_tron_conformance_vectors() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/p256verify_test_vectors.json")).unwrap();
    let vectors = vectors.as_array().unwrap();
    assert_eq!(vectors.len(), 782);
    for v in vectors {
        let name = v["Name"].as_str().unwrap();
        let input = hex::decode(v["Input"].as_str().unwrap()).unwrap();
        let expected = hex::decode(v["Expected"].as_str().unwrap()).unwrap();
        assert_eq!(
            PrecompileImpl::P256Verify.effective_energy_cost(&input, &OSAKA).unwrap(),
            v["Gas"].as_u64().unwrap(),
            "{name}"
        );
        assert_eq!(PrecompileImpl::P256Verify.execute(&input, &OSAKA).unwrap(), expected, "{name}");
    }
}
