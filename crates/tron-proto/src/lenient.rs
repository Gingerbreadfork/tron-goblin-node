//! java-tron-compatible lenient protobuf decoding for contract messages.
//!
//! java-tron's generated message parsers (protobuf-java 3.x
//! `Builder.mergeFrom(CodedInputStream, ...)`) dispatch a `switch` over the
//! **full field key** — `(field_number << 3) | wire_type` — and route any
//! key that matches no known field's exact tag to
//! `GeneratedMessageV3.parseUnknownField`, which calls
//! `CodedInputStream.skipField(tag)`. `skipField` advances past the field
//! purely by its wire type (varint, 64-bit, length-delimited, group, 32-bit)
//! and throws `InvalidProtocolBufferException` only on a structurally invalid
//! wire type. The crucial consequence: a key whose field number IS known but
//! whose wire type does NOT match that field's declared type matches no
//! `case`, so it is treated as an unknown field and silently skipped — the
//! field keeps its default value.
//!
//! prost dispatches `Message::merge_field` on the field number alone and then
//! validates the wire type, so the same input makes prost reject the whole
//! message with a wire-type-mismatch `DecodeError`. That is stricter than
//! java and causes a consensus divergence: a `TriggerSmartContract` whose
//! call-data was mis-encoded under field 3 (`call_value`, varint) as a
//! length-delimited value (tag `0x1a`) is committed by java (it skips the
//! stray field and executes an empty-data call) but rejected pre-VM by a
//! naive prost decode.
//!
//! [`decode_lenient`] reproduces java's parser exactly: it walks the wire
//! stream, keeps every field prost can merge (known field number + matching
//! wire type, including the packed/unpacked pair prost accepts for repeatable
//! scalars), and skips by wire type any other field — mirroring
//! `skipField`. Structurally invalid input (truncation, invalid wire type,
//! unbalanced groups) still errors, matching java's `InvalidProtocolBufferException`,
//! so the decoder is never *more* lenient than java.

use prost::bytes::Buf;
use prost::encoding::{decode_key, skip_field, DecodeContext};
use prost::{DecodeError, Message};

/// Decode a protobuf message the way java-tron's generated parser does:
/// fields with a known number and matching wire type are merged, every other
/// (well-formed) field is skipped by its wire type, and structurally invalid
/// input is rejected.
///
/// This is used for the contract messages carried in `Transaction.Contract
/// .parameter` so that node decode behaviour is byte-for-byte consistent with
/// java on malformed-but-skippable fields (see module docs).
pub fn decode_lenient<T: Message + Default>(mut buf: &[u8]) -> Result<T, DecodeError> {
    // Fast path: a well-formed message decodes strictly and is byte-for-byte
    // identical to java's parse (the overwhelming majority of txs). The lenient
    // field-filtering walk below is only needed when strict decode fails on a
    // malformed-but-skippable field that java skips (see module docs), so run
    // it solely as the fallback — avoiding the extra walk + allocation per tx.
    if let Ok(msg) = T::decode(buf) {
        return Ok(msg);
    }

    let mut filtered: Vec<u8> = Vec::with_capacity(buf.len());
    let ctx = DecodeContext::default();

    while buf.has_remaining() {
        // java's generated `switch (tag)` has a `case 0: done = true` arm: a
        // field key of zero terminates the message. prost's `decode_key`
        // rejects tag 0, so detect the sentinel before decoding the key to
        // avoid being stricter than java.
        if buf[0] == 0 {
            break;
        }

        // Remember the field's start so its raw key+value bytes can be copied
        // verbatim into the filtered stream if it is a field we keep.
        let field_start = buf;

        let (tag, wire_type) = decode_key(&mut buf)?;

        // `skip_field` advances `buf` past the field's value and validates the
        // wire structure exactly like `CodedInputStream.skipField` — it errors
        // on truncation, an invalid wire type, or an unbalanced group. The
        // value slice between the key and the post-skip cursor is the field
        // body; capture it before skipping so a kept field can be re-emitted.
        let value_start = buf;
        skip_field(wire_type, tag, &mut buf, ctx.clone())?;
        let field_len = field_start.len() - buf.len();
        let value_len = value_start.len() - buf.len();
        let raw_field = &field_start[..field_len];
        let mut value_buf = &value_start[..value_len];

        // Decide keep-vs-skip the way java's `switch` does: a field is kept
        // only if prost can merge it into a fresh message — i.e. the field
        // number is known AND the wire type matches what that field accepts.
        // Any other field (unknown number, or known number with a mismatched
        // wire type, exactly the divergence case) is dropped, mirroring
        // `parseUnknownField` -> `skipField`. The merge runs on a throwaway
        // value purely as the acceptance oracle; the kept bytes come from the
        // original stream so no re-encoding can alter them.
        let mut probe = T::default();
        if probe
            .merge_field(tag, wire_type, &mut value_buf, ctx.clone())
            .is_ok()
        {
            filtered.extend_from_slice(raw_field);
        }
    }

    T::decode(filtered.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CreateSmartContract, TriggerSmartContract};
    use hex_literal::hex;

    /// The exact `TriggerSmartContract` `Any.value` from mainnet block
    /// 83,449,286 tx
    /// 295eab54767bb6a9ef482beff84c8aced52fa57814d9bb414c0f5d96b0ca1813.
    /// Field 1 (owner) and field 2 (contract = USDT) are well formed; the
    /// ERC-20 `transfer` calldata that should have been field 4 (`data`,
    /// tag 0x22) was mis-encoded under field 3 (`call_value`) as a
    /// length-delimited value (tag 0x1a, 68 bytes), and two further stray
    /// varint fields (numbers 14 and 18) trail it. None of fields 3, 14, 18
    /// match a `TriggerSmartContract` field's exact tag, so java skips all
    /// three and executes an empty-data call; the strict prost decode
    /// rejected the whole message on the field-3 wire-type mismatch.
    const MALFORMED_TRIGGER: [u8; 129] = hex!(
        "0a1541255e50c4cd410c17222826da304619449c28ad8c"
        "121541a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        "1a44a9059cbb00000000000000000000000033db753723de253573902fb8b23ccd7e88461abb"
        "0000000000000000000000000000000000000000000000000000000000981d68"
        "7084928ee7ea33"
        "900180c2d72f"
    );

    #[test]
    fn skips_known_field_with_mismatched_wire_type() {
        // Sanity: the strict prost decode must reject this input, otherwise
        // the lenient path is not exercising the divergence.
        assert!(
            TriggerSmartContract::decode(MALFORMED_TRIGGER.as_slice()).is_err(),
            "strict prost decode is expected to reject the mis-encoded field 3"
        );

        let c: TriggerSmartContract =
            decode_lenient(&MALFORMED_TRIGGER).expect("java skips the stray field");

        assert_eq!(
            c.owner_address,
            hex!("41255e50c4cd410c17222826da304619449c28ad8c"),
            "owner address must decode (field 1)"
        );
        assert_eq!(
            c.contract_address,
            hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c"),
            "contract address (USDT) must decode (field 2)"
        );
        // The mis-encoded field 3 (and the stray fields 14/18) are skipped,
        // so every value field keeps its default — java's view
        // (gettransactionbyid: data_len=0, call_value absent).
        assert!(c.data.is_empty(), "data must be empty — java skips field 3");
        assert_eq!(c.call_value, 0, "call_value must default to 0");
        assert_eq!(c.call_token_value, 0, "call_token_value must default to 0");
        assert_eq!(c.token_id, 0, "token_id must default to 0");
    }

    #[test]
    fn well_formed_trigger_keeps_data() {
        // A normal TriggerSmartContract with proper field-4 `data` must still
        // decode its data — no regression from the lenient path.
        let original = TriggerSmartContract {
            owner_address: hex!("41255e50c4cd410c17222826da304619449c28ad8c").to_vec(),
            contract_address: hex!("41a614f803b6fd780986a42c78ec9c7f77e6ded13c").to_vec(),
            call_value: 1234,
            data: hex!("a9059cbbdeadbeef").to_vec(),
            call_token_value: 0,
            token_id: 0,
        };
        let bytes = original.encode_to_vec();
        let c: TriggerSmartContract = decode_lenient(&bytes).expect("well-formed decodes");
        assert_eq!(c, original, "lenient decode is identity on valid input");
        assert_eq!(c.data, hex!("a9059cbbdeadbeef"), "field-4 data preserved");
        assert_eq!(c.call_value, 1234, "field-3 call_value preserved");
    }

    #[test]
    fn create_smart_contract_roundtrips() {
        // Lenient decode must be the identity on any well-formed message, not
        // just TriggerSmartContract.
        let original = CreateSmartContract {
            owner_address: hex!("41255e50c4cd410c17222826da304619449c28ad8c").to_vec(),
            new_contract: None,
            call_token_value: 7,
            token_id: 1000001,
        };
        let bytes = original.encode_to_vec();
        let c: CreateSmartContract = decode_lenient(&bytes).expect("well-formed decodes");
        assert_eq!(c, original);
    }

    #[test]
    fn truncated_input_still_errors() {
        // java throws InvalidProtocolBufferException on a truncated field; the
        // lenient decoder must not paper over a genuinely malformed stream.
        // A length-delimited field 1 declaring 0x44 (68) bytes but with the
        // body cut short is a structural error, exactly like the mainnet tx's
        // field but truncated.
        let truncated = hex!("0a44a9059cbb"); // claims 68 bytes, supplies 4
        assert!(
            decode_lenient::<TriggerSmartContract>(&truncated).is_err(),
            "truncated length-delimited body must error like java"
        );
    }

    #[test]
    fn invalid_wire_type_still_errors() {
        // Wire type 6 is invalid in protobuf; java's skipField throws and
        // prost's decode_key rejects it. Lenient decode must propagate.
        let invalid = hex!("0e00"); // tag 1, wire type 6 (invalid)
        assert!(
            decode_lenient::<TriggerSmartContract>(&invalid).is_err(),
            "invalid wire type must error like java"
        );
    }
}
