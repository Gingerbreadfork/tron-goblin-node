//! One-shot extractor for the Sapling spend/output verifying keys.
//!
//! Usage:
//!   cargo run --bin extract_sapling_vk -- \
//!     <path-to-sapling-spend.params> <path-to-sapling-output.params>
//!
//! Reads each .params file (the full proving+verifying key bundle from
//! Zcash's Sapling MPC ceremony), pulls out just the `VerifyingKey`
//! portion, and writes it to `assets/sapling-spend.vk` /
//! `assets/sapling-output.vk` in the same directory as this binary.
//!
//! The output bytes use bellman's `VerifyingKey::write` format
//! (uncompressed G1/G2 points), which is what we deserialize at runtime.

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;

use bellman::groth16::Parameters;
use bls12_381::Bls12;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!(
            "usage: extract_sapling_vk <sapling-spend.params> <sapling-output.params>"
        );
        std::process::exit(1);
    }
    let spend_in = PathBuf::from(&args[1]);
    let output_in = PathBuf::from(&args[2]);

    // assets/ lives next to Cargo.toml for the tron-tvm crate.
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let spend_out = crate_root.join("assets/sapling-spend.vk");
    let output_out = crate_root.join("assets/sapling-output.vk");

    extract(&spend_in, &spend_out, "spend");
    extract(&output_in, &output_out, "output");
}

fn extract(input: &PathBuf, output: &PathBuf, label: &str) {
    println!("Reading {} parameters from {:?}", label, input);
    let f = File::open(input).expect("open input .params");
    let reader = BufReader::new(f);
    // `Parameters::read(reader, false)` skips point-on-curve checks for
    // speed; we're operating on a known-good file shipped with java-tron.
    let params: Parameters<Bls12> =
        Parameters::read(reader, false).expect("decode Parameters");

    let out = File::create(output).expect("create output .vk");
    let mut writer = BufWriter::new(out);
    params.vk.write(&mut writer).expect("write vk");
    let size = std::fs::metadata(output).unwrap().len();
    println!(
        "Wrote {} bytes to {:?} (ic_len = {})",
        size,
        output,
        params.vk.ic.len()
    );
}
