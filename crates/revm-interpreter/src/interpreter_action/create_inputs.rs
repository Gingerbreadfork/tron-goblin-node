use context_interface::CreateScheme;
use core::cell::OnceCell;
use primitives::{keccak256, Address, Bytes, B256, U256};

/// Inputs for a create call
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CreateInputs {
    /// Caller address of the EVM
    caller: Address,
    /// The create scheme
    scheme: CreateScheme,
    /// The value to transfer
    value: U256,
    /// The init code of the contract
    init_code: Bytes,
    /// The gas limit of the call
    gas_limit: u64,
    /// State gas reservoir (EIP-8037). Passed from parent frame to child frame.
    reservoir: u64,
    /// **TRON fork** — the `SmartContract.version` the created contract's init
    /// frame executes as. java's nested CREATE child inherits the *parent's*
    /// version (`Program.java:915`: `setContractVersion(getContractVersion())`),
    /// so the CREATE opcode handler stamps this from the executing frame's
    /// version. A top-level CREATE forces 1 (`VMActuator.java:415`). Governs the
    /// child's EIP-150 1/64 retention + GASPRICE. Default `0` (legacy).
    tron_contract_version: i32,
    /// **TRON fork** — pre-`ALLOW_TVM_ISTANBUL` (#41) override for the CREATE2
    /// address-derivation sender. java `Program.createContract2`:
    /// `senderAddress = allowTvmIstanbul() ? getContextAddress() :
    /// getCallerAddress()`. ONLY the `generateContractAddress2` input changes —
    /// value/nonce stay on `caller` (java's `createContractImpl` sources the
    /// endowment from `getContextAddress()`). `None` → use `caller`
    /// (post-Istanbul, or any non-CREATE2 create).
    tron_create2_sender: Option<Address>,
    /// Cached created address. This is computed lazily and cached to avoid
    /// redundant keccak computations when inspectors call `created_address`.
    #[cfg_attr(feature = "serde", serde(skip))]
    cached_address: OnceCell<Address>,
    /// Cached init code hash. Shared between `created_address()` (for CREATE2)
    /// and frame initialization (for `ExtBytecode`), ensuring keccak256 of the
    /// init code is computed at most once.
    #[cfg_attr(feature = "serde", serde(skip))]
    cached_init_code_hash: OnceCell<B256>,
}

impl CreateInputs {
    /// Creates a new `CreateInputs` instance.
    pub const fn new(
        caller: Address,
        scheme: CreateScheme,
        value: U256,
        init_code: Bytes,
        gas_limit: u64,
        reservoir: u64,
    ) -> Self {
        Self {
            caller,
            scheme,
            value,
            init_code,
            gas_limit,
            reservoir,
            tron_contract_version: 0,
            tron_create2_sender: None,
            cached_address: OnceCell::new(),
            cached_init_code_hash: OnceCell::new(),
        }
    }

    /// **TRON fork** — the `SmartContract.version` the created contract's init
    /// frame runs as (see the field doc). Stamped by the CREATE opcode handler.
    pub const fn tron_contract_version(&self) -> i32 {
        self.tron_contract_version
    }

    /// **TRON fork** — set the version the init frame runs as.
    pub const fn set_tron_contract_version(&mut self, version: i32) {
        self.tron_contract_version = version;
    }

    /// **TRON fork** — set the pre-Istanbul CREATE2 address-derivation sender
    /// override (see the field doc). Set by the CREATE2 opcode handler when
    /// `ALLOW_TVM_ISTANBUL` (#41) is not yet active.
    pub const fn set_tron_create2_sender(&mut self, sender: Option<Address>) {
        self.tron_create2_sender = sender;
    }

    /// Returns the address that this create call will create.
    ///
    /// The result is cached to avoid redundant keccak computations.
    ///
    /// **TRON fork:** CREATE2 uses java-tron's
    /// `WalletUtil.generateContractAddress2` layout, which is
    /// `sha3omit12(senderAddress21 ++ salt ++ sha3(initCode))` where
    /// `senderAddress21` is the 21-byte `0x41`-prefixed creating-contract
    /// address. Byte-for-byte this is the standard EVM CREATE2 preimage with
    /// the `0xff` domain-separator replaced by `0x41` (verified live against
    /// java-tron deposit-shell factories). The plain CREATE branch here is
    /// only reached by inspectors as an informational best-effort guess — the
    /// consensus address comes from the host's tx-id/nonce derivation in
    /// `make_create_frame`, since TRON has no account nonce.
    pub fn created_address(&self, nonce: u64) -> Address {
        *self.cached_address.get_or_init(|| match self.scheme {
            CreateScheme::Create => self.caller.create(nonce),
            CreateScheme::Create2 { salt } => {
                // Pre-Istanbul (#41) the derivation sender is the CALLER of the
                // executing frame (`tron_create2_sender`), not the executing
                // contract; post-Istanbul and by default it is `caller` (= the
                // executing contract). java `Program.createContract2`.
                let sender = self.tron_create2_sender.unwrap_or(self.caller);
                tron_create2_address(&sender, B256::from(salt.to_be_bytes()), self.init_code_hash())
            }
            CreateScheme::Custom { address } => address,
        })
    }

    /// Returns the keccak256 hash of the init code.
    ///
    /// The result is cached so that `created_address()` and frame initialization
    /// share a single hash computation.
    pub fn init_code_hash(&self) -> B256 {
        *self
            .cached_init_code_hash
            .get_or_init(|| keccak256(self.init_code.as_ref()))
    }

    /// Returns the caller address of the EVM.
    pub const fn caller(&self) -> Address {
        self.caller
    }

    /// Returns the create scheme of the EVM.
    pub const fn scheme(&self) -> CreateScheme {
        self.scheme
    }

    /// Returns the value to transfer.
    pub const fn value(&self) -> U256 {
        self.value
    }

    /// Returns the init code of the contract.
    pub const fn init_code(&self) -> &Bytes {
        &self.init_code
    }

    /// Returns the gas limit of the call.
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    /// Set call
    pub const fn set_call(&mut self, caller: Address) {
        self.caller = caller;
        self.cached_address = OnceCell::new();
    }

    /// Set scheme
    pub const fn set_scheme(&mut self, scheme: CreateScheme) {
        self.scheme = scheme;
        self.cached_address = OnceCell::new();
    }

    /// Set value
    pub const fn set_value(&mut self, value: U256) {
        self.value = value;
    }

    /// Set init code
    pub fn set_init_code(&mut self, init_code: Bytes) {
        self.init_code = init_code;
        self.cached_address = OnceCell::new();
        self.cached_init_code_hash = OnceCell::new();
    }

    /// Set gas limit
    pub const fn set_gas_limit(&mut self, gas_limit: u64) {
        self.gas_limit = gas_limit;
    }

    /// Returns the state gas reservoir (EIP-8037).
    pub const fn reservoir(&self) -> u64 {
        self.reservoir
    }

    /// Set the state gas reservoir (EIP-8037).
    pub const fn set_reservoir(&mut self, reservoir: u64) {
        self.reservoir = reservoir;
    }
}

/// java-tron CREATE2 contract-address derivation
/// (`WalletUtil.generateContractAddress2`).
///
/// `0x41 || sha3omit12( 0x41 ++ caller(20) ++ salt(32) ++ keccak(initCode)(32) )`.
/// The returned [`Address`] is the 20-byte EVM half (`[12..]` of the hash); the
/// `0x41` TRON prefix is reattached at commit. The preimage is the standard
/// EVM CREATE2 preimage with the `0xff` domain byte replaced by `0x41`.
pub fn tron_create2_address(caller: &Address, salt: B256, init_code_hash: B256) -> Address {
    let mut buf = [0u8; 1 + 20 + 32 + 32];
    buf[0] = 0x41;
    buf[1..21].copy_from_slice(caller.as_slice());
    buf[21..53].copy_from_slice(salt.as_slice());
    buf[53..85].copy_from_slice(init_code_hash.as_slice());
    Address::from_word(keccak256(buf))
}

/// java-tron nested-CREATE contract-address derivation
/// (`TransactionUtil.generateContractAddress(rootTxId, nonce)`).
///
/// `0x41 || sha3omit12( rootTxId(32) ++ nonce_be(8) )`. The returned
/// [`Address`] is the 20-byte EVM half. `nonce` is java-tron's per-transaction
/// internal-transaction counter (NOT an account nonce — TRON accounts have
/// none), supplied by the host.
pub fn tron_create_address(root_tx_id: B256, nonce: u64) -> Address {
    let mut buf = [0u8; 32 + 8];
    buf[..32].copy_from_slice(root_tx_id.as_slice());
    buf[32..].copy_from_slice(&nonce.to_be_bytes());
    Address::from_word(keccak256(buf))
}

#[cfg(test)]
mod tron_address_tests {
    use super::*;

    fn b256_hex(s: &str) -> B256 {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        B256::from(out)
    }
    fn addr_hex(s: &str) -> Address {
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        Address::from(out)
    }

    /// CREATE2 preimage differs from EVM only in the leading domain byte
    /// (`0x41` vs `0xff`), so the TRON address must NOT equal alloy's.
    #[test]
    fn create2_differs_from_evm_by_domain_byte() {
        let caller = addr_hex("34ed0e191531d0410613527d3d491dda030d8b5c");
        let salt = b256_hex("00000000000000000000000000000000000000000000000000000000deadbeef");
        let code_hash =
            b256_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
        let tron = tron_create2_address(&caller, salt, code_hash);
        let evm = caller.create2(salt.0, code_hash);
        assert_ne!(tron, evm);
        // Recompute the TRON preimage by hand to pin the byte layout.
        let mut buf = Vec::new();
        buf.push(0x41u8);
        buf.extend_from_slice(caller.as_slice());
        buf.extend_from_slice(salt.as_slice());
        buf.extend_from_slice(code_hash.as_slice());
        assert_eq!(tron, Address::from_word(keccak256(&buf)));
    }

    /// VM-3: pre-Istanbul CREATE2 derives the address from the frame's CALLER,
    /// not the executing contract. `tron_create2_sender` overrides ONLY the
    /// address-derivation sender; with no override it is `caller`.
    #[test]
    fn tron_create2_sender_override_changes_the_derivation_sender() {
        let context = addr_hex("1111111111111111111111111111111111111111");
        let frame_caller = addr_hex("2222222222222222222222222222222222222222");
        let salt = U256::from(7u64);
        let code = Bytes::from_static(&[0x60, 0x00]); // PUSH1 0
        let salt_b256 = B256::from(salt.to_be_bytes());
        let code_hash = keccak256(code.as_ref());

        // Default (post-Istanbul / no override): derived from `caller` (=context).
        let default_inputs =
            CreateInputs::new(context, CreateScheme::Create2 { salt }, U256::ZERO, code.clone(), 0, 0);
        assert_eq!(
            default_inputs.created_address(0),
            tron_create2_address(&context, salt_b256, code_hash),
        );

        // Pre-Istanbul override: derived from the frame's caller instead.
        let mut overridden =
            CreateInputs::new(context, CreateScheme::Create2 { salt }, U256::ZERO, code, 0, 0);
        overridden.set_tron_create2_sender(Some(frame_caller));
        assert_eq!(
            overridden.created_address(0),
            tron_create2_address(&frame_caller, salt_b256, code_hash),
        );
        assert_ne!(
            default_inputs.created_address(0),
            overridden.created_address(0),
            "the sender override must change the CREATE2 address"
        );
    }

    /// Nested-CREATE address pins the `rootTxId || nonce_be8` layout.
    #[test]
    fn nested_create_layout() {
        let root = b256_hex("9e3e34b3ab07c8b6918b7d1e84624895cd105a16d13817864e4721c90fcc8784");
        let got = tron_create_address(root, 7);
        let mut buf = Vec::new();
        buf.extend_from_slice(root.as_slice());
        buf.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(got, Address::from_word(keccak256(&buf)));
    }
}
