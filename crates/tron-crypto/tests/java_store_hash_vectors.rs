//! Hash primitives pinned against java-tron's `common/utils` test suite.
//!
//! java reference: `org.tron.common.utils.Sha256HashTest#testHash`, whose
//! vector comes from TWP-001 (the TRON address-encoding spec). The double
//! SHA-256 it pins is the checksum step of every base58check address on the
//! chain, so a drift here would make us reject valid addresses (and accept
//! invalid ones) rather than merely fail a test.

use tron_crypto::{decode_address, encode_address, encode_check, sha256, Address};

/// The 21-byte address body from TWP-001, in java's own hex spelling.
const TWP001_ADDRESS_HEX: &str = "A0E11973395042BA3C0B52B4CDF4E15EA77818F275";

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector is valid hex")
}

/// `Sha256HashTest#testHash`: `hash0 = sha256(addr)` and
/// `hash1 = sha256(hash0)` for the TWP-001 address, asserted against literal
/// digests. java's `Sha256Hash.hash` is selected by the crypto-engine flag;
/// both engines produce the same SHA-256, so a single vector pins both.
#[test]
fn sha256_twp001_single_and_double_hash_match_java_tron() {
    let input = unhex(TWP001_ADDRESS_HEX);
    assert_eq!(input.len(), 21, "TWP-001 address body is 21 bytes");

    let hash0 = sha256(&input);
    assert_eq!(
        hash0.to_vec(),
        unhex("CD5D4A7E8BE869C00E17F8F7712F41DBE2DDBD4D8EC36A7280CD578863717084")
    );

    let hash1 = sha256(&hash0);
    assert_eq!(
        hash1.to_vec(),
        unhex("10AE21E887E8FE30C591A22A5F8BB20EB32B2A739486DC5F3810E00BBDB58C5C")
    );
}

/// The first four bytes of the double hash are the base58check checksum, so
/// the TWP-001 vector must reappear verbatim in the encoded address. This ties
/// the raw digest above to the encoding path that actually consumes it.
#[test]
fn base58check_checksum_is_the_first_four_bytes_of_the_double_sha256() {
    let input = unhex(TWP001_ADDRESS_HEX);
    let double = sha256(&sha256(&input));
    let checksum = &double[..4];
    assert_eq!(checksum, &[0x10, 0xAE, 0x21, 0xE8]);

    // Encoding appends exactly that checksum, and decoding accepts it.
    let encoded = encode_check(&input);
    let decoded = tron_crypto::decode_check(&encoded).unwrap();
    assert_eq!(decoded, input);

    // A one-bit change in the checksum must be rejected rather than tolerated.
    let mut corrupt = input.clone();
    corrupt.extend_from_slice(&[checksum[0] ^ 0x01, checksum[1], checksum[2], checksum[3]]);
    let bad = bs58::encode(&corrupt).into_string();
    assert!(
        tron_crypto::decode_check(&bad).is_err(),
        "a corrupted checksum must fail to decode"
    );
}

/// Round-tripping the TWP-001 address through the typed address encoder must
/// preserve the exact 21 bytes, including the `0x41` mainnet prefix byte
/// (`Wallet.getAddressPreFixByte`) that java asserts on throughout its store
/// tests via `randomBytes`.
#[test]
fn twp001_address_round_trips_through_base58check() {
    let mut raw = [0u8; 21];
    raw.copy_from_slice(&unhex(TWP001_ADDRESS_HEX));
    // TWP-001's example body starts with 0xA0, not the mainnet 0x41 prefix, so
    // pin the round trip on both: the codec must not special-case the prefix.
    let addr = Address::from_raw(raw);
    let encoded = encode_address(&addr);
    assert_eq!(decode_address(&encoded).unwrap(), addr);

    let mut mainnet = raw;
    mainnet[0] = 0x41;
    let mainnet_addr = Address::from_raw(mainnet);
    let encoded_mainnet = encode_address(&mainnet_addr);
    assert!(
        encoded_mainnet.starts_with('T'),
        "a 0x41-prefixed address must base58-encode to a leading 'T': {encoded_mainnet}"
    );
    assert_eq!(decode_address(&encoded_mainnet).unwrap(), mainnet_addr);
    assert_eq!(decode_address(&encoded_mainnet).unwrap().as_bytes()[0], 0x41);
}

/// `Sha256HashTest#testMultiThreadingHash` hashes the same input 70,000 times
/// across threads and asserts every result matches. The property it is really
/// pinning is that the hash function holds no shared mutable state.
#[test]
fn sha256_is_deterministic_across_threads() {
    let input = unhex(TWP001_ADDRESS_HEX);
    let expected = unhex("CD5D4A7E8BE869C00E17F8F7712F41DBE2DDBD4D8EC36A7280CD578863717084");

    let handles: Vec<_> = (0..7)
        .map(|_| {
            let input = input.clone();
            let expected = expected.clone();
            std::thread::spawn(move || {
                for _ in 0..2_000 {
                    assert_eq!(sha256(&input).to_vec(), expected);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("hashing thread must not panic");
    }
}

/// java's `Sha256Hash` exposes `hashTwice(engine, empty)` and friends on
/// zero-length input; the empty-string digest is the standard SHA-256 value and
/// must not be special-cased to zeros.
#[test]
fn sha256_of_empty_input_is_the_standard_digest_not_zeros() {
    let d = sha256(&[]);
    assert_eq!(
        d.to_vec(),
        unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_ne!(d, [0u8; 32]);
    // Double-hashing empty input is likewise well-defined.
    assert_eq!(
        sha256(&d).to_vec(),
        unhex("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
    );
}
