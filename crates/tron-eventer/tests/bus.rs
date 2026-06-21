//! End-to-end: register two listeners (channel + a counting test
//! listener), emit one trigger of each kind, verify both listeners
//! observed all triggers in order.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tron_eventer::listeners::{ChannelListener, TriggerMessage};
use tron_eventer::{
    BlockEvent, ContractEvent, ContractLogEvent, EventBus, EventListener,
    SolidifiedBlockEvent, TransactionEvent,
};

#[derive(Default)]
struct CountingListener {
    blocks: AtomicUsize,
    txs: AtomicUsize,
    logs: AtomicUsize,
    events: AtomicUsize,
    solid: AtomicUsize,
}

impl EventListener for CountingListener {
    fn on_block(&self, _: &BlockEvent) {
        self.blocks.fetch_add(1, Ordering::SeqCst);
    }
    fn on_transaction(&self, _: &TransactionEvent) {
        self.txs.fetch_add(1, Ordering::SeqCst);
    }
    fn on_contract_log(&self, _: &ContractLogEvent) {
        self.logs.fetch_add(1, Ordering::SeqCst);
    }
    fn on_contract_event(&self, _: &ContractEvent) {
        self.events.fetch_add(1, Ordering::SeqCst);
    }
    fn on_solidified_block(&self, _: &SolidifiedBlockEvent) {
        self.solid.fetch_add(1, Ordering::SeqCst);
    }
}

fn sample_block() -> BlockEvent {
    BlockEvent::new(7, &[0xab; 32], 1_700_000_000_000, 5, vec![[0xcd; 32], [0xef; 32]])
}

fn sample_tx() -> TransactionEvent {
    TransactionEvent {
        trigger_name: tron_eventer::trigger::names::TRANSACTION,
        time_stamp: 1_700_000_000_000,
        transaction_id: hex::encode([0xcd; 32]),
        block_hash: hex::encode([0xab; 32]),
        block_number: 7,
        transaction_index: 0,
        contract_type: "TransferContract".into(),
        result: "SUCCESS".into(),
        contract_result: String::new(),
        from_address: hex::encode([0x41u8; 21]),
        to_address: hex::encode([0x42u8; 21]),
        contract_address: String::new(),
        fee_limit: 0,
        energy_usage: 0,
        origin_energy_usage: 0,
        energy_usage_total: 0,
        energy_fee: 0,
        net_usage: 268,
        net_fee: 0,
        contract_call_value: 1000,
        asset_name: String::new(),
        asset_amount: 0,
        latest_solidified_block_number: 5,
        data: String::new(),
    }
}

#[tokio::test]
async fn bus_fans_out_to_every_listener_in_registration_order() {
    let counter = Arc::new(CountingListener::default());
    let (channel_listener, mut rx) = ChannelListener::pair(16);
    let bus = EventBus::builder()
        .add_arc(counter.clone() as Arc<dyn EventListener>)
        .add(channel_listener)
        .build();
    assert_eq!(bus.listener_count(), 2);
    assert!(!bus.is_empty());

    let block = sample_block();
    let tx = sample_tx();
    bus.emit_block(&block);
    bus.emit_transaction(&tx);
    bus.emit_solidified_block(&SolidifiedBlockEvent::new(7, 1_700_000_000_000));

    // Counting listener saw all three.
    assert_eq!(counter.blocks.load(Ordering::SeqCst), 1);
    assert_eq!(counter.txs.load(Ordering::SeqCst), 1);
    assert_eq!(counter.solid.load(Ordering::SeqCst), 1);

    // Channel listener saw all three in order.
    let msg1 = rx.recv().await.expect("first");
    assert!(matches!(msg1, TriggerMessage::Block(_)));
    let msg2 = rx.recv().await.expect("second");
    assert!(matches!(msg2, TriggerMessage::Transaction(_)));
    let msg3 = rx.recv().await.expect("third");
    assert!(matches!(msg3, TriggerMessage::SolidifiedBlock(_)));
}

#[tokio::test]
async fn empty_bus_is_a_safe_noop() {
    // Default-constructed bus has no listeners — every emit is a noop,
    // matches the "feature disabled" code path the executor will use.
    let bus = EventBus::default();
    assert!(bus.is_empty());
    bus.emit_block(&sample_block());
    bus.emit_transaction(&sample_tx());
    // No assertion — just verifying no panic.
}

#[tokio::test]
async fn channel_listener_drops_when_full_but_does_not_panic() {
    let (l, mut rx) = ChannelListener::pair(2);
    let bus = EventBus::builder().add(l).build();
    let block = sample_block();
    // Push 5 events into a 2-slot channel. The first 2 land; the
    // remainder are dropped with a warn! (no panic, no executor stall).
    for _ in 0..5 {
        bus.emit_block(&block);
    }
    let mut received = 0;
    while rx.try_recv().is_ok() {
        received += 1;
    }
    assert_eq!(received, 2, "exactly the buffered slots were delivered");
}

#[test]
fn transaction_event_serializes_to_java_tron_camelcase() {
    let tx = sample_tx();
    let j = serde_json::to_value(&tx).unwrap();
    // Spot-check every field renamed to camelCase.
    for field in [
        "triggerName",
        "timeStamp",
        "transactionId",
        "blockHash",
        "blockNumber",
        "transactionIndex",
        "contractType",
        "result",
        "contractResult",
        "fromAddress",
        "toAddress",
        "contractAddress",
        "feeLimit",
        "energyUsage",
        "originEnergyUsage",
        "energyUsageTotal",
        "energyFee",
        "netUsage",
        "netFee",
        "contractCallValue",
        "assetName",
        "assetAmount",
        "latestSolidifiedBlockNumber",
        "data",
    ] {
        assert!(j.get(field).is_some(), "missing camelCase field {field} in {j}");
    }
}
