//! Energy-accounting and failure-classification parity against java-tron's own
//! VM test suite.
//!
//! java-tron's `framework/src/test/java/org/tron/common/runtime/vm/` tests pin
//! exact `receipt.energyUsageTotal` values for deploying and triggering real
//! solc-0.4 bytecode, together with the exact failure classification — whether
//! a failure is a REVERT (refunds the unused budget) or an exception that
//! burns the entire fee limit. Those numbers are the tightest available
//! specification of TRON's charging rules: every opcode price, the
//! 200-energy-per-byte code-deposit charge, the memory-expansion curve, the
//! call-energy forwarding rule and the "illegal operation spends all energy"
//! rule must all be simultaneously correct to reproduce them.
//!
//! Every test below cites the java test it mirrors and reuses that test's
//! bytecode verbatim, so the expected values are java's, not ours.
//!
//! java's `Constant.TEST_CONF` leaves `allowTvmConstantinople` at its `Args`
//! default of 0, so these tests describe the pre-`ALLOW_TVM_CONSTANTINOPLE`
//! (#26) era. Cases whose expected outcome is era-independent run on the
//! modern stores; the two `ChargeTest` cases that turn on the pre-#26
//! `ArithmeticException` flavour of a bad endowment run on pre-#26 stores and
//! say so.

use std::sync::Arc;

use tron_chainbase::{
    AccountStore, CodeStore, ContractStateStore, DelegatedResourceStore, DelegationStore,
    DynamicPropertiesStore, KvBackend, MemBackend, StorageRowStore, WitnessStore,
};
use tron_crypto::address::Address;
use tron_proto::{
    smart_contract::Abi, Account, CreateSmartContract, SmartContract, TriggerSmartContract,
};
use tron_tvm::execute::{execute_create, execute_trigger, VmBlockEnv, VmOutcome, VmStores};

fn mem() -> Arc<dyn KvBackend> {
    Arc::new(MemBackend::new())
}

fn stores_with_constantinople(on: bool) -> VmStores {
    let dynamic_properties = Arc::new(DynamicPropertiesStore::new(mem()));
    dynamic_properties.put_long(b"ALLOW_TVM_CONSTANTINOPLE", i64::from(on));
    VmStores {
        accounts: Arc::new(AccountStore::new(mem())),
        code: Arc::new(CodeStore::new(mem())),
        storage: Arc::new(StorageRowStore::new(mem())),
        witnesses: Arc::new(WitnessStore::new(mem())),
        contract_state: Arc::new(ContractStateStore::new(mem())),
        dynamic_properties,
        delegated_resources: Arc::new(DelegatedResourceStore::new(mem())),
        delegated_resource_account_index: None,
        delegation: Arc::new(DelegationStore::new(mem())),
        block_index: None,
        contracts: None,
        votes: None,
        reward_vi: None,
        abi: None,
    }
}

fn fresh_stores() -> VmStores {
    stores_with_constantinople(true)
}

/// java's `EnergyWhen*Test` / `ChargeTest` use `feeLimit = 1_000_000_000` sun
/// at the default 100 sun/energy price, i.e. a 10,000,000 energy budget.
const ENERGY_LIMIT: u64 = 10_000_000;
/// `EnergyWhenSendAndTransferTest.sendTest` / `.transferTest` drop the fee
/// limit to `100_000_000` sun — a 1,000,000 energy budget.
const SMALL_ENERGY_LIMIT: u64 = 1_000_000;

fn owner_address(stores: &VmStores) -> [u8; 21] {
    let mut owner_bytes = [0u8; 21];
    owner_bytes[0] = 0x41;
    owner_bytes[1..].fill(0xa0);
    let owner = Address::from_raw(owner_bytes);
    stores
        .accounts
        .put(
            &owner,
            &Account {
                address: owner.as_bytes().to_vec(),
                balance: 100_000_000_000_000,
                ..Default::default()
            },
        )
        .unwrap();
    owner_bytes
}

fn env() -> VmBlockEnv {
    VmBlockEnv {
        block_number: 100,
        block_timestamp_ms: 1_700_000_000_000,
        ..Default::default()
    }
}

/// Deploy solc output the way java's `TvmTestUtils.deployContract*` does: the
/// whole hex blob is the init code and `consumeUserResourcePercent` is 100.
fn deploy_with_limit(
    stores: &VmStores,
    owner: [u8; 21],
    code_hex: &str,
    call_value: i64,
    tx_id: [u8; 32],
    energy_limit: u64,
) -> VmOutcome {
    let create = CreateSmartContract {
        owner_address: owner.to_vec(),
        new_contract: Some(SmartContract {
            origin_address: owner.to_vec(),
            contract_address: vec![],
            abi: Some(Abi::default()),
            bytecode: hex_bytes(code_hex),
            call_value,
            consume_user_resource_percent: 100,
            name: "test".into(),
            origin_energy_limit: 1_000_000_000,
            code_hash: vec![],
            trx_hash: vec![],
            version: 1,
        }),
        call_token_value: 0,
        token_id: 0,
    };
    execute_create(stores, env(), &create, &tx_id, energy_limit)
}

fn deploy(stores: &VmStores, owner: [u8; 21], code_hex: &str, call_value: i64,
    tx_id: [u8; 32]) -> VmOutcome {
    deploy_with_limit(stores, owner, code_hex, call_value, tx_id, ENERGY_LIMIT)
}

/// Call `signature` with `params` appended, mirroring java's
/// `TvmTestUtils.parseAbi(sig, params)`: the 4-byte selector followed by the
/// raw ABI word(s).
fn trigger_with_limit(
    stores: &VmStores,
    owner: [u8; 21],
    contract: &[u8],
    signature: &str,
    params: &str,
    call_value: i64,
    energy_limit: u64,
) -> VmOutcome {
    let mut data = tron_crypto::hash::keccak256(signature.as_bytes())[..4].to_vec();
    data.extend_from_slice(&hex_bytes(params));
    let t = TriggerSmartContract {
        owner_address: owner.to_vec(),
        contract_address: contract.to_vec(),
        call_value,
        data,
        call_token_value: 0,
        token_id: 0,
    };
    execute_trigger(stores, env(), &t, energy_limit)
}

fn trigger(stores: &VmStores, owner: [u8; 21], contract: &[u8], signature: &str,
    call_value: i64) -> VmOutcome {
    trigger_with_limit(stores, owner, contract, signature, "", call_value, ENERGY_LIMIT)
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn energy_of(outcome: &VmOutcome) -> u64 {
    match outcome {
        VmOutcome::Success { energy_used, .. }
        | VmOutcome::Revert { energy_used, .. }
        | VmOutcome::TransferFailed { energy_used }
        | VmOutcome::Halt { energy_used, .. }
        | VmOutcome::Timeout { energy_used, .. } => *energy_used,
        other => panic!("no energy for {other:?}"),
    }
}

/// Assert an outcome is a successful deploy and hand back the 21-byte TRON
/// contract address java's `result.getContractAddress()` would return.
fn deployed_address(outcome: &VmOutcome) -> Vec<u8> {
    match outcome {
        VmOutcome::Success { return_data, .. } => return_data.clone(),
        other => panic!("expected a successful deploy, got {other:?}"),
    }
}

#[track_caller]
fn assert_energy(outcome: &VmOutcome, expected: u64) {
    assert_eq!(energy_of(outcome), expected, "energy mismatch for {outcome:?}");
}

/// java `result.getRuntime().getResult().isRevert() == true` with a null
/// exception: the frame reverted, so only the energy consumed up to the
/// REVERT is charged.
#[track_caller]
fn assert_revert(outcome: &VmOutcome) {
    assert!(matches!(outcome, VmOutcome::Revert { .. }), "expected Revert, got {outcome:?}");
}

/// java `isRevert() == false` with a non-null exception: an exception that is
/// not a revert, which `VMActuator` settles by spending the whole budget.
#[track_caller]
fn assert_halt(outcome: &VmOutcome) {
    assert!(matches!(outcome, VmOutcome::Halt { .. }), "expected Halt, got {outcome:?}");
}

#[track_caller]
fn assert_success(outcome: &VmOutcome) {
    assert!(matches!(outcome, VmOutcome::Success { .. }), "expected Success, got {outcome:?}");
}

const THROW_CODE: &str = "6080604052348015600f57600080fd5b5060838061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
00000000000000000000000000000000000000000000000000000060003504166350bff6bf81146043575b600080fd5b3480\
15604e57600080fd5b506055603e565b0000a165627a7a72305820f51282c5910e3ff1b5f2e9509f3cf23c7035027aae1947\
ab46e5a9252fb061eb0029";

const REQUIRE_CODE: &str = "6080604052348015600f57600080fd5b5060838061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
000000000000000000000000000000000000000000000000000000600035041663357815c481146043575b600080fd5b3480\
15604e57600080fd5b506055603e565b0000a165627a7a7230582054141931bcc37d4f266815f02d2fb113f5af20825cbce4\
5d3b0f2fe90ac0145d0029";

const THIS_FN_MSGCALL_CODE: &str = "608060405234801561001057600080fd5b50610121806100206000396000f30060806040526004361060485763ffffffff7c\
01000000000000000000000000000000000000000000000000000000006000350416632b813bc08114604d5780635df83fe7\
146061575b600080fd5b348015605857600080fd5b50605f6073565b005b348015606c57600080fd5b50605f6075565bfe5b\
3073ffffffffffffffffffffffffffffffffffffffff16632b813bc06113886040518263ffffffff167c0100000000000000\
000000000000000000000000000000000000000000028152600401600060405180830381600088803b15801560db57600080\
fd5b5087f115801560ee573d6000803e3d6000fd5b50505050505600a165627a7a7230582087d830c44fb566498789b212e3\
d0374f7a7589a2efdda11b3a4c03051b57891a0029";

const THAT_FN_MSGCALL_CODE: &str = "608060405234801561001057600080fd5b506101e6806100206000396000f3006080604052600436106100405763ffffffff\
7c01000000000000000000000000000000000000000000000000000000006000350416637dbc1cb88114610045575b600080\
fd5b34801561005157600080fd5b5061005a61005c565b005b6000610066610108565b604051809103906000f08015801561\
0082573d6000803e3d6000fd5b5090508073ffffffffffffffffffffffffffffffffffffffff16632b813bc0611388604051\
8263ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040160006040518083\
0381600088803b1580156100ec57600080fd5b5087f1158015610100573d6000803e3d6000fd5b505050505050565b604051\
60a3806101188339019056006080604052348015600f57600080fd5b5060858061001e6000396000f3006080604052600436\
10603e5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416632b813bc081\
146043575b600080fd5b348015604e57600080fd5b5060556057565b005bfe00a165627a7a72305820c02c76575c2a0ada80\
c3f6db47f885cece6c254d1e7c79eb6ddc1c1d4e70ebae0029a165627a7a72305820cf879e62f738b44636adf61bd4b2fb38\
c10f027d2a4484d58baf44a06dc97bd90029";

const NEW_CONTRACT_CODE: &str = "608060405234801561001057600080fd5b5060d58061001f6000396000f3006080604052600436106100405763ffffffff7c\
01000000000000000000000000000000000000000000000000000000006000350416635d10a9e68114610045575b600080fd\
5b34801561005157600080fd5b5061005a61005c565b005b6000610066610087565b604051809103906000f0801580156100\
82573d6000803e3d6000fd5b505050565b6040516013806100978339019056006080604052348015600f57600080fd5b50fe\
00a165627a7a72305820685ff8f74890f671deb4d3881a4b72ab0daac2ab0d36112e1ebdf98a43ac4d940029";

const RECEIVE_TRX_NO_PAYABLE_CODE: &str = "608060405234801561001057600080fd5b506101f5806100206000396000f3006080604052600436106100405763ffffffff\
7c01000000000000000000000000000000000000000000000000000000006000350416638a46bf6d8114610045575b600080\
fd5b61004d61004f565b005b600061005961015f565b604051809103906000f080158015610075573d6000803e3d6000fd5b\
5060408051600481526024810182526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
167f60f59d44000000000000000000000000000000000000000000000000000000001781529151815193945073ffffffffff\
ffffffffffffffffffffffffffffff851693600193829180838360005b8381101561010e5781810151838201526020016100\
f6565b50505050905090810190601f16801561013b5780820380516001836020036101000a031916815260200191505b5091\
505060006040518083038185875af11515925061015c91505057600080fd5b50565b604051605b8061016f83390190560060\
80604052348015600f57600080fd5b50603e80601d6000396000f3006080604052348015600f57600080fd5b500000a16562\
7a7a72305820a82006ee5ac783bcea7085501eaed33360b3120278f1f39e611afedc9f4a693b0029a165627a7a72305820a5\
0d9536f182fb6aefc737fdc3a675630e75a08de88deb6b1bee6d4b6dff04730029";

const REVERT_CODE: &str = "608060405234801561001057600080fd5b5060b68061001f6000396000f30060806040526004361060485763ffffffff7c01\
0000000000000000000000000000000000000000000000000000000060003504166312065fe08114604d578063a26388bb14\
6071575b600080fd5b348015605857600080fd5b50605f6085565b60408051918252519081900360200190f35b348015607c\
57600080fd5b5060836048565b005b3031905600a165627a7a7230582059cab3a7a5851a7852c728ec8729456a04dc022674\
976f3f26bfd51491dbf1080029";

const OUT_OF_INDEX_CODE: &str = "608060405234801561001057600080fd5b5060c58061001f6000396000f300608060405260043610603e5763ffffffff7c01\
000000000000000000000000000000000000000000000000000000006000350416639a4e1fa081146043575b600080fd5b34\
8015604e57600080fd5b5060556057565b005b60408051600a80825261016082019092526060916020820161014080388339\
019050509050600a81600a815181101515608c57fe5b60209081029091010152505600a165627a7a723058201aaf6626083e\
32afa834a13d3365784c509d10f57ce1024f88c697cf0718795e0029";

const BYTES_N_CODE: &str = "6080604052348015600f57600080fd5b50609f8061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
0000000000000000000000000000000000000000000000000000006000350416631e76e10781146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005b7201234500000000000000000000000000000000601460008282fe00a165627a\
7a72305820a1c7c81d642cc0aa11c43d63614a5b3c018e4af84700af4bfde5f2efb18b55130029";

const DIV_ZERO_CODE: &str = "6080604052348015600f57600080fd5b50608b8061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
000000000000000000000000000000000000000000000000000000600035041663b87d948d81146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005b60008080600afe00a165627a7a7230582084ed35f2e244d6721bb5f5fcaf53d2\
37ea050b3de84d5cc7fee74584fd2ff31f0029";

const SHIFT_BY_NEGATIVE_CODE: &str = "6080604052348015600f57600080fd5b50608e8061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
000000000000000000000000000000000000000000000000000000600035041663e88e362a81146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005b600919600081610400fe00a165627a7a7230582086c99cfe65e26909bb0fb3a2\
bdaf2385ad8dfff72680adab954063a4fe1d549b0029";

const ENUM_TYPE_CODE: &str = "6080604052348015600f57600080fd5b5060898061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
0000000000000000000000000000000000000000000000000000006000350416635a43cddc81146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005b6000600afe00a165627a7a72305820b24a4d459b753723d300f56c408c6120d5\
ef0c7ddb166d66ccf4277a76ad83ed0029";

const FUNCTION_POINTER_CODE: &str = "6080604052348015600f57600080fd5b5060988061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
000000000000000000000000000000000000000000000000000000600035041663e9ad8ee781146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005b606a606660018263ffffffff16565b5050565bfe00a165627a7a723058201c89\
82fa288ec7aad86b1d1992ecc5d08c4b22e4fe037981f91aff8bcbd900680029";

const ASSERT_CODE: &str = "6080604052348015600f57600080fd5b5060858061001e6000396000f300608060405260043610603e5763ffffffff7c0100\
0000000000000000000000000000000000000000000000000000006000350416632b813bc081146043575b600080fd5b3480\
15604e57600080fd5b5060556057565b005bfe00a165627a7a723058208ce7511bd3a946a22baaba2b4521cbf29d2481ad52\
887c5567e422cd89726eda0029";

const OUT_OF_MEM_CODE: &str = "608060405234801561001057600080fd5b5060ca8061001f6000396000f300608060405260043610603e5763ffffffff7c01\
00000000000000000000000000000000000000000000000000000000600035041663e31fcf3c81146043575b600080fd5b34\
8015604e57600080fd5b506058600435605a565b005b600060605b8282101560995760408051623004008082526306008020\
82019092529060208201630600800080388339019050506001909201919050605f565b5050505600a165627a7a723058209e\
5d294a7bf5133b304bc6851c749cd5e1f4748230405755e6bd2e31549ae1d00029";

const OVERFLOW_CODE: &str = "608060405234801561001057600080fd5b50610100806100206000396000f300608060405260043610603f576000357c0100\
000000000000000000000000000000000000000000000000000000900463ffffffff1680638040cac4146044575b600080fd\
5b604a604c565b005b6000678ac7230489e80000605d607f565b6040518091039082f0801580156077573d6000803e3d6000\
fd5b509050905050565b60405160468061008f833901905600608060405260358060116000396000f3006080604052600080\
fd00a165627a7a723058201738d6aa899dc00d4e99de944eb74d30a9ba1fcae37b99dc6299d95e992ca8b40029a165627a7a\
7230582068390137ba70dfc460810603eba8500b050ed3cd01e66f55ec07d387ec1cd2750029";

const NEGATIVE_CODE: &str = "608060405234801561001057600080fd5b50610154806100206000396000f300608060405260043610603f576000357c0100\
000000000000000000000000000000000000000000000000000000900463ffffffff1680638f7d8a1c146044575b600080fd\
5b604a604c565b005b6000807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff91507f3a26\
492830c137b6cedfdd0e23db0e9c7c214e4fd1de32de8ceece1678b771b38260405180828152602001915050604051809103\
90a18160b060d3565b6040518091039082f08015801560ca573d6000803e3d6000fd5b50905090505050565b604051604680\
6100e3833901905600608060405260358060116000396000f3006080604052600080fd00a165627a7a72305820ef54aac72e\
fff56dbe894e7218d009a87368bb70338bb385db5d3dec9927bc2c0029a165627a7a723058201620679ac2ae640d0a6c26e9\
cb4523e98eb0de8fff26975c5bb4c7fda1c98d720029";

const CALL_DEPTH_CODE: &str = "608060405234801561001057600080fd5b50610174806100206000396000f3006080604052600436106100325763ffffffff\
60e060020a6000350416633a3c47188114610037578063eede0f0114610051575b600080fd5b34801561004357600080fd5b\
5061004f600435610069565b005b34801561005d57600080fd5b5061004f6004356100d7565b60008113156100d45730633a\
3c47186107d05a03600184036040518363ffffffff1660e060020a0281526004018082815260200191505060006040518083\
0381600088803b1580156100ba57600080fd5b5087f11580156100ce573d6000803e3d6000fd5b50505050505b50565b3073\
ffffffffffffffffffffffffffffffffffffffff16633a3c4718826040518263ffffffff1660e060020a0281526004018082\
8152602001915050600060405180830381600087803b15801561012d57600080fd5b505af1158015610141573d6000803e3d\
6000fd5b50505050505600a165627a7a72305820510367f4437b1af16931cacc744eb6f3102d72f0c369aa795a4dc49a7f90\
a3e90029";

const CALL_DEPTH_WIDTH_CODE: &str = "608060405261000c61005b565b604051809103906000f080158015610028573d6000803e3d6000fd5b5060008054600160a0\
60020a031916600160a060020a039290921691909117905534801561005557600080fd5b5061006b565b6040516102658061\
02c683390190565b61024c8061007a6000396000f30060806040526004361061004b5763ffffffff7c010000000000000000\
000000000000000000000000000000000000000060003504166370ed9d828114610050578063f84df1931461006a575b6000\
80fd5b34801561005c57600080fd5b50610068600435610082565b005b34801561007657600080fd5b506100686004356101\
09565b600081111561010657306370ed9d826107d05a03600184036040518363ffffffff167c010000000000000000000000\
000000000000000000000000000000000002815260040180828152602001915050600060405180830381600088803b158015\
6100ec57600080fd5b5087f1158015610100573d6000803e3d6000fd5b50505050505b50565b60005b8181101561021c5760\
4080517f70ed9d82000000000000000000000000000000000000000000000000000000008152601483016004820152905130\
916370ed9d8291602480830192600092919082900301818387803b15801561016e57600080fd5b505af1158015610182573d\
6000803e3d6000fd5b505060008054604080517ff84df1930000000000000000000000000000000000000000000000000000\
00008152600a87016004820152905173ffffffffffffffffffffffffffffffffffffffff909216945063f84df19393506024\
80820193929182900301818387803b1580156101f857600080fd5b505af115801561020c573d6000803e3d6000fd5b505060\
01909201915061010c9050565b50505600a165627a7a72305820ad701f54dc539d976cc2af0443d5d190dbe727ce2e24d66f\
3e2390dfd79859640029608060405234801561001057600080fd5b50610245806100206000396000f3006080604052600436\
1061004b5763ffffffff7c010000000000000000000000000000000000000000000000000000000060003504166370ed9d82\
8114610050578063f84df1931461006a575b600080fd5b34801561005c57600080fd5b50610068600435610082565b005b34\
801561007657600080fd5b50610068600435610109565b600081111561010657306370ed9d826107d05a0360018403604051\
8363ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152602001\
915050600060405180830381600088803b1580156100ec57600080fd5b5087f1158015610100573d6000803e3d6000fd5b50\
505050505b50565b60006014821161018a57604080517f70ed9d820000000000000000000000000000000000000000000000\
00000000008152601484016004820152905130916370ed9d8291602480830192600092919082900301818387803b15801561\
016d57600080fd5b505af1158015610181573d6000803e3d6000fd5b50505050610215565b5060005b818110156102155760\
4080517ff84df193000000000000000000000000000000000000000000000000000000008152601319830160048201529051\
309163f84df19391602480830192600092919082900301818387803b1580156101f157600080fd5b505af115801561020557\
3d6000803e3d6000fd5b50506001909201915061018e9050565b50505600a165627a7a72305820a9e7e1401001d6c131ebf4\
727fbcedede08d16416dc0447cef60e0b9516c6a260029";

const CREATE_DEPTH_WIDTH_CODE: &str = "608060405234801561001057600080fd5b506103f0806100206000396000f3006080604052600436106100405763ffffffff\
7c0100000000000000000000000000000000000000000000000000000000600035041663b505dee58114610045575b600080\
fd5b34801561005157600080fd5b5061005d60043561005f565b005b6000805b828210156101255761007361012a565b6040\
51809103906000f08015801561008f573d6000803e3d6000fd5b5090508073ffffffffffffffffffffffffffffffffffffff\
ff1663da6d107a836040518263ffffffff167c01000000000000000000000000000000000000000000000000000000000281\
5260040180828152602001915050600060405180830381600087803b15801561010157600080fd5b505af115801561011557\
3d6000803e3d6000fd5b5050600190930192506100639050565b505050565b60405161028a8061013b833901905600608060\
405234801561001057600080fd5b5061026a806100206000396000f3006080604052600436106100405763ffffffff7c0100\
000000000000000000000000000000000000000000000000000000600035041663da6d107a8114610045575b600080fd5b34\
801561005157600080fd5b5061005d60043561005f565b005b60008082111561010f573063da6d107a6107d05a0360018503\
6040518363ffffffff167c010000000000000000000000000000000000000000000000000000000002815260040180828152\
602001915050600060405180830381600088803b1580156100ca57600080fd5b5087f11580156100de573d6000803e3d6000\
fd5b50505050506100eb61013b565b604051809103906000f080158015610107573d6000803e3d6000fd5b50905061013756\
5b61011761013b565b604051809103906000f080158015610133573d6000803e3d6000fd5b5090505b5050565b60405160f4\
8061014b8339019056006080604052348015600f57600080fd5b506000805b6064821015604a5760226050565b6040518091\
03906000f080158015603d573d6000803e3d6000fd5b5060019092019190506014565b5050605f565b6040516052806100a2\
83390190565b60358061006d6000396000f3006080604052600080fd00a165627a7a723058203565a8abc553526f8113ab8a\
3f432963d88cee07cafce0ebfc61173d3797b84700296080604052348015600f57600080fd5b50603580601d6000396000f3\
006080604052600080fd00a165627a7a723058204855bba321c7dee00dfa91caa8926cf07c38c541a11ba36d3b2a4687acaa\
909c0029a165627a7a7230582093af601a9196cffc9bf82bcae83557d7f5aedeec639129c27826f38c1e2a2ea00029a16562\
7a7a7230582071d51c39c93b0aba5baeacea0b2bd5ca5342d028bb834046eca92975a3517a4c0029";

const CALL_VALUE_CODE: &str = "608060405261000c61004e565b604051809103906000f080158015610028573d6000803e3d6000fd5b5060008054600160a0\
60020a031916600160a060020a039290921691909117905561005d565b60405160d68061020b83390190565b61019f806100\
6c6000396000f3006080604052600436106100325763ffffffff60e060020a60003504166306ce93af811461003757806340\
de221c1461004e575b600080fd5b34801561004357600080fd5b5061004c610063565b005b34801561005a57600080fd5b50\
61004c610103565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffff\
ffffffffffffffffffffffffff1663cd95478c600a6003906040518363ffffffff1660e060020a0281526004016020604051\
808303818589803b1580156100d357600080fd5b5088f11580156100e7573d6000803e3d6000fd5b5050505050506040513d\
60208110156100ff57600080fd5b5050565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffff\
ff1673ffffffffffffffffffffffffffffffffffffffff1663b993e5e2600a6003906040518363ffffffff1660e060020a02\
81526004016020604051808303818589803b1580156100d357600080fd00a165627a7a72305820cb5f172ca9f81235a8b33e\
e1ddef9dd1b398644cf61228569356ff051bfaf3d10029608060405260c4806100126000396000f300608060405260043610\
60485763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663b993e5e28114\
604d578063cd95478c146065575b600080fd5b6053606b565b60408051918252519081900360200190f35b60536070565b60\
2a90565b6000805b600a81101560945760008181526020819052604090208190556001016074565b50905600a165627a7a72\
3058205ded543feb546472be4e116e713a2d46b8dafc823ca31256e67a1be92a6752730029";

const SEND_TRANSFER_CODE: &str = "608060405261000c61004e565b604051809103906000f080158015610028573d6000803e3d6000fd5b5060008054600160a0\
60020a031916600160a060020a039290921691909117905561005d565b604051606f806101c583390190565b610159806100\
6c6000396000f3006080604052600436106100565763ffffffff7c0100000000000000000000000000000000000000000000\
00000000000060003504166312065fe0811461005b57806333182e8f14610082578063e3d237f914610099575b600080fd5b\
34801561006757600080fd5b506100706100ae565b60408051918252519081900360200190f35b34801561008e57600080fd\
5b506100976100b3565b005b3480156100a557600080fd5b506100976100f9565b303190565b6000805460405173ffffffff\
ffffffffffffffffffffffffffffffff90911691906127109082818181858883f193505050501580156100f6573d6000803e\
3d6000fd5b50565b6000805460405173ffffffffffffffffffffffffffffffffffffffff9091169190612710908281818185\
8883f150505050505600a165627a7a72305820677efa58ed7b277b589fe6626cb77f930caeb0f75c3ab638bfe07292db961a\
8200296080604052605e8060116000396000f3006080604052600160008181526020527fada5013122d395ba3c54772283fb\
069b10426056ef8ca54750cb9bb552a59e7d550000a165627a7a7230582029b27c10c1568d590fa66bc0b7d42537a314c78d\
028f59a188fa411f7fc15c4f0029";

const ENDLESS_LOOP_CODE: &str = "608060405234801561001057600080fd5b506000808190555060fa806100266000396000f300608060405260043610604957\
6000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680630242f35114604e\
578063230796ae146076575b600080fd5b348015605957600080fd5b50606060a0565b604051808281526020019150506040\
5180910390f35b348015608157600080fd5b50609e6004803603810190808035906020019092919050505060a9565b005b60\
008054905090565b806000819055505b60011560cb576001600080828254019250508190555060b1565b505600a165627a7a\
72305820290a38c9bbafccaf6c7f752ab56d229e354da767efb72715ee9fdb653b9f4b6c0029";

// ---------------------------------------------------------------------------
// EnergyWhenRequireStyleTest — failures that REVERT, charging only the energy
// actually consumed.
// ---------------------------------------------------------------------------

/// java `EnergyWhenRequireStyleTest.throwTest`: deploying the `throw` contract
/// costs 26,275 energy (131 bytes of deployed code at 200 each, plus 75 for
/// the constructor), and calling `testThrow()` reverts for 124.
#[test]
fn require_style_throw() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, THROW_CODE, 0, [0x11; 32]);
    assert_energy(&d, 26275);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testThrow()", 0);
    assert_energy(&t, 124);
    assert_revert(&t);
}

/// java `EnergyWhenRequireStyleTest.requireTest`: a failing `require(2==1)`
/// reverts for 124 energy, exactly like `throw` — solc 0.4 lowers both to the
/// same `REVERT(0,0)` handler.
#[test]
fn require_style_require() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, REQUIRE_CODE, 0, [0x12; 32]);
    assert_energy(&d, 26275);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testRequire()", 0);
    assert_energy(&t, 124);
    assert_revert(&t);
}

/// java `EnergyWhenRequireStyleTest.revertTest`: an explicit `revert()` costs
/// 146 energy and reverts.
#[test]
fn require_style_revert() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, REVERT_CODE, 0, [0x13; 32]);
    assert_energy(&d, 36481);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testRevert()", 0);
    assert_energy(&t, 146);
    assert_revert(&t);
}

/// java `EnergyWhenRequireStyleTest.thisFunctionViaMessageCallTest`: an
/// inner `CALL` to a function that hits `assert` burns only the 5,000 energy
/// forwarded to that frame; the caller then reverts. Total 5,339 — the key
/// property being that the inner INVALID does NOT escalate to spending the
/// whole 10,000,000 budget.
#[test]
fn require_style_this_function_via_message_call() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, THIS_FN_MSGCALL_CODE, 0, [0x14; 32]);
    assert_energy(&d, 57905);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testThisFunctionViaMessageCall()", 0);
    assert_energy(&t, 5339);
    assert_revert(&t);
}

/// java `EnergyWhenRequireStyleTest.thatFunctionViaMessageCallTest`: the same
/// containment through a freshly `new`-ed sub-contract — 64,125 energy, then a
/// revert.
#[test]
fn require_style_that_function_via_message_call() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, THAT_FN_MSGCALL_CODE, 0, [0x15; 32]);
    assert_energy(&d, 97341);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testThatFunctionViaMessageCall()", 0);
    assert_energy(&t, 64125);
    assert_revert(&t);
}

/// java `EnergyWhenRequireStyleTest.newContractTest1`: a `new` whose
/// constructor hits `assert` is NOT contained — CREATE forwards the whole
/// remaining budget, the INVALID burns it, and the transaction settles at the
/// full 10,000,000 with an exception rather than a revert.
#[test]
fn require_style_new_contract_burns_full_budget() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, NEW_CONTRACT_CODE, 0, [0x16; 32]);
    assert_energy(&d, 42687);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testNewContract()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenRequireStyleTest.receiveTrxWithoutPayableTest`: deploying a
/// contract with a non-payable constructor while sending 10 sun reverts after
/// only 42 energy. Re-deploying with zero value succeeds for 100,341, and
/// `testFallback()` — which `call`s a non-existent function with value on a
/// contract with no payable fallback — reverts for 51,833.
#[test]
fn require_style_receive_trx_without_payable() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);

    let d = deploy(&stores, owner, RECEIVE_TRX_NO_PAYABLE_CODE, 10, [0x17; 32]);
    assert_energy(&d, 42);
    assert_revert(&d);

    let d2 = deploy(&stores, owner, RECEIVE_TRX_NO_PAYABLE_CODE, 0, [0x18; 32]);
    assert_energy(&d2, 100341);
    let addr = deployed_address(&d2);

    let t = trigger(&stores, owner, &addr, "testFallback()", 10);
    assert_energy(&t, 51833);
    assert_revert(&t);
}

// ---------------------------------------------------------------------------
// EnergyWhenAssertStyleTest — assert-style failures lower to the INVALID
// opcode (0xfe), which is an illegal operation: java classifies it as an
// exception (never a revert) and spends the entire fee limit.
// ---------------------------------------------------------------------------

/// java `EnergyWhenAssertStyleTest.outOfIndexTest`: an out-of-bounds array
/// index spends the whole 10,000,000 budget via `IllegalOperationException`.
#[test]
fn assert_style_out_of_index() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, OUT_OF_INDEX_CODE, 0, [0x21; 32]);
    assert_energy(&d, 39487);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testOutOfIndex()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.bytesNTest`: indexing past the end of a
/// `bytes16` spends the whole budget.
#[test]
fn assert_style_bytes_n() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, BYTES_N_CODE, 0, [0x22; 32]);
    assert_energy(&d, 31875);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testbytesN()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.divZeroTest`: division by zero spends the
/// whole budget. Note this is solc's guard lowering to INVALID, not the EVM
/// `DIV` opcode (which returns 0).
#[test]
fn assert_style_div_zero() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, DIV_ZERO_CODE, 0, [0x23; 32]);
    assert_energy(&d, 27875);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testDivZero()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.shiftByNegativeTest`: shifting by a
/// negative amount spends the whole budget.
#[test]
fn assert_style_shift_by_negative() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, SHIFT_BY_NEGATIVE_CODE, 0, [0x24; 32]);
    assert_energy(&d, 28475);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testShiftByNegative()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.enumTypeTest`: casting an out-of-range
/// value to an enum spends the whole budget.
#[test]
fn assert_style_enum_type() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, ENUM_TYPE_CODE, 0, [0x25; 32]);
    assert_energy(&d, 27475);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testEnumType()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.functionPointerTest`: calling an
/// uninitialised internal function pointer spends the whole budget.
#[test]
fn assert_style_function_pointer() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, FUNCTION_POINTER_CODE, 0, [0x26; 32]);
    assert_energy(&d, 30475);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testFunctionPointer()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.assertTest`: a plain failing `assert`
/// spends the whole budget.
#[test]
fn assert_style_assert() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, ASSERT_CODE, 0, [0x27; 32]);
    assert_energy(&d, 26675);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testAssert()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `EnergyWhenAssertStyleTest.outOfMemTest`: allocating an absurd amount
/// of memory raises `OutOfMemoryException`, which — like the illegal-operation
/// family — spends the whole budget rather than reverting.
#[test]
fn assert_style_out_of_mem() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, OUT_OF_MEM_CODE, 0, [0x28; 32]);
    assert_energy(&d, 40487);
    let addr = deployed_address(&d);
    let t = trigger_with_limit(
        &stores,
        owner,
        &addr,
        "testMem(uint256)",
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        ENERGY_LIMIT,
    );
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

// ---------------------------------------------------------------------------
// ChargeTest — deep/wide call and create trees, and the pre-#26 endowment
// exceptions.
// ---------------------------------------------------------------------------

/// java `ChargeTest.testCallDepth`: a self-recursing `CALL` chain that hits
/// the 64-frame depth limit costs exactly 27,743 energy and reverts. Pins the
/// depth cap together with the 1/64 energy-forwarding rule — a wrong cap or a
/// wrong forwarding fraction moves this number.
#[test]
fn charge_call_depth() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, CALL_DEPTH_CODE, 0, [0x31; 32]);
    assert_energy(&d, 74517);
    let addr = deployed_address(&d);
    let t = trigger_with_limit(
        &stores,
        owner,
        &addr,
        "Call(int256)",
        "0000000000000000000000000000000000000000000000000000000000002710",
        0,
        ENERGY_LIMIT,
    );
    assert_energy(&t, 27743);
    assert_revert(&t);
}

/// java `ChargeTest.testCallDepthAndWidth`: a mixed depth/width call tree
/// across two contracts settles at exactly 243,698 energy and succeeds.
#[test]
fn charge_call_depth_and_width() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, CALL_DEPTH_WIDTH_CODE, 0, [0x32; 32]);
    assert_energy(&d, 286450);
    let addr = deployed_address(&d);
    let t = trigger_with_limit(
        &stores,
        owner,
        &addr,
        "Call(uint256)",
        "000000000000000000000000000000000000000000000000000000000000000a",
        0,
        ENERGY_LIMIT,
    );
    assert_energy(&t, 243698);
    assert_success(&t);
}

/// java `ChargeTest.testCreateDepthAndWidth`: a nested `CREATE` tree costs
/// exactly 4,481,164 energy. The dominant term is the 200-per-byte code
/// deposit repeated across every child deploy, so this pins the deposit
/// charge on nested creates as well as the create-depth behaviour.
#[test]
fn charge_create_depth_and_width() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, CREATE_DEPTH_WIDTH_CODE, 0, [0x33; 32]);
    assert_energy(&d, 201839);
    let addr = deployed_address(&d);
    let t = trigger_with_limit(
        &stores,
        owner,
        &addr,
        "testCreate(uint256)",
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        ENERGY_LIMIT,
    );
    assert_energy(&t, 4481164);
    assert_success(&t);
}

/// java `ChargeTest.testOverflow`: `(new subContract).value(10 ether)()` from a
/// contract that cannot cover the endowment. Pre-`ALLOW_TVM_CONSTANTINOPLE`
/// java raises `ArithmeticException` — not a revert — and spends the entire
/// fee limit.
#[test]
fn charge_overflow_endowment_spends_all_energy() {
    let stores = stores_with_constantinople(false);
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, OVERFLOW_CODE, 0, [0x34; 32]);
    assert_energy(&d, 51293);
    let addr = deployed_address(&d);
    let t = trigger(&stores, owner, &addr, "testOverflow()", 20_000_000_000);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}

/// java `ChargeTest.testNegative`: `(new subContract).value(uint(-1))()`.
/// The endowment reinterpreted as an unsigned 256-bit value is far outside
/// the signed-64-bit range TRON balances live in; pre-#26 that is an
/// `ArithmeticException` which spends the entire fee limit, both when the
/// outer call carries zero value and when it carries a negative one.
#[test]
fn charge_negative_endowment_spends_all_energy() {
    let stores = stores_with_constantinople(false);
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, NEGATIVE_CODE, 0, [0x35; 32]);
    assert_energy(&d, 68111);
    let addr = deployed_address(&d);

    let t = trigger(&stores, owner, &addr, "testNegative()", 0);
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);

    let t2 = trigger(&stores, owner, &addr, "testNegative()", -100);
    assert_energy(&t2, ENERGY_LIMIT);
    assert_halt(&t2);
}

// ---------------------------------------------------------------------------
// EnergyWhenSendAndTransferTest — `.value().gas()` forwarding, and the
// difference between `send` (returns false) and `transfer` (reverts).
// ---------------------------------------------------------------------------

/// java `EnergyWhenSendAndTransferTest.callValueTest`: `.value(10).gas(3)()`
/// forwards the 2,300-energy stipend on top of the 3 requested. A callee that
/// fits inside the stipend costs 7,370 in total; one that does not runs out
/// and the caller reverts at 9,459 — the unused budget is still refunded.
#[test]
fn send_and_transfer_call_value_stipend() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, CALL_VALUE_CODE, 10_000_000, [0x41; 32]);
    assert_energy(&d, 174639);
    let addr = deployed_address(&d);

    let simple = trigger(&stores, owner, &addr, "simpleCall()", 0);
    assert_energy(&simple, 7370);

    let complex = trigger(&stores, owner, &addr, "complexCall()", 0);
    assert_energy(&complex, 9459);
    assert_revert(&complex);
}

/// java `EnergyWhenSendAndTransferTest.sendTest`: `address.send()` to a
/// contract whose fallback runs out of the 2,300 stipend returns false and
/// does NOT revert the caller — 7,025 energy, no exception.
#[test]
fn send_and_transfer_send_does_not_revert() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy_with_limit(&stores, owner, SEND_TRANSFER_CODE, 1000, [0x42; 32],
        SMALL_ENERGY_LIMIT);
    assert_energy(&d, 140194);
    let addr = deployed_address(&d);

    let t = trigger_with_limit(&stores, owner, &addr, "doSend()", "", 0, SMALL_ENERGY_LIMIT);
    assert_energy(&t, 7025);
    assert_success(&t);
}

/// java `EnergyWhenSendAndTransferTest.transferTest`: the same failing
/// transfer through `address.transfer()` instead reverts the caller, at 7,030
/// energy — 5 more than `send`, which is the extra work of checking the
/// return value and reverting.
#[test]
fn send_and_transfer_transfer_reverts() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy_with_limit(&stores, owner, SEND_TRANSFER_CODE, 1000, [0x43; 32],
        SMALL_ENERGY_LIMIT);
    assert_energy(&d, 140194);
    let addr = deployed_address(&d);

    let t = trigger_with_limit(&stores, owner, &addr, "doTransfer()", "", 0, SMALL_ENERGY_LIMIT);
    assert_energy(&t, 7030);
    assert_revert(&t);
}

// ---------------------------------------------------------------------------
// EnergyWhenTimeoutStyleTest
// ---------------------------------------------------------------------------

/// java `EnergyWhenTimeoutStyleTest.endlessLoopTest`: an unbounded storage
/// loop. java's assertion is disjunctive (`OutOfTimeException` OR
/// `OutOfEnergyException`) because its 80ms wall clock may trip first; with no
/// wall clock in play the deterministic outcome is running the budget out, so
/// the whole fee limit is spent and the result is an exception, not a revert.
#[test]
fn timeout_style_endless_loop_exhausts_budget() {
    let stores = fresh_stores();
    let owner = owner_address(&stores);
    let d = deploy(&stores, owner, ENDLESS_LOOP_CODE, 0, [0x51; 32]);
    assert_energy(&d, 55107);
    let addr = deployed_address(&d);
    let t = trigger_with_limit(
        &stores,
        owner,
        &addr,
        "setVote(uint256)",
        "0000000000000000000000000000000000000000000000000000000000000001",
        0,
        ENERGY_LIMIT,
    );
    assert_energy(&t, ENERGY_LIMIT);
    assert_halt(&t);
}
