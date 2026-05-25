//! `tron-wallet` — keystore + signing CLI.
//!
//! Subcommands:
//! * `keygen [--out FILE] [--password PW] [--light]` — generate a new
//!   secp256k1 keypair, print the address, and (if `--out` given)
//!   write a v3 keystore JSON file encrypted under `--password`.
//! * `address [--priv HEX | --keystore FILE [--password PW]]` — derive
//!   the TRON Base58Check address for a given key.
//! * `sign --keystore FILE --tx HEX [--password PW]` — decode a hex
//!   protobuf `Transaction`, sign it, print the signed transaction's
//!   hex.
//! * `send --keystore FILE --tx HEX --rpc URL [--password PW]` — sign
//!   and POST `broadcastTransaction` to `--rpc`.
//!
//! Password discovery: the `--password` flag wins (useful in
//! scripts/tests but echoes in shell history). Otherwise the env var
//! `TRON_WALLET_PASSWORD` is read. When neither is set AND stdin is a
//! TTY, `rpassword` prompts interactively (echo suppressed). Non-TTY
//! invocations (pipes, CI) fall through to the "no password" error
//! path rather than hanging on stdin. Env var pattern
//! is already enough for non-interactive use.
//!
//! All subcommands exit with status 0 on success and 1 on any error.
//! Output is a JSON object on stdout, errors go to stderr.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;
use tron_wallet::{
    address_from_private, address_to_base58, broadcast_signed_tx, generate_private_key,
    sign_transaction_bytes, Keystore,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("{}", usage());
        return ExitCode::from(1);
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .expect("build runtime");
    let result = match args[1].as_str() {
        "keygen" => cmd_keygen(&args[2..]),
        "address" => cmd_address(&args[2..]),
        "sign" => cmd_sign(&args[2..]),
        "send" => rt.block_on(cmd_send(&args[2..])),
        "keystore" => cmd_keystore(&args[2..]),
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            return ExitCode::from(0);
        }
        other => Err(format!("unknown subcommand '{other}'\n\n{}", usage())),
    };
    match result {
        Ok(v) => {
            // Print the result JSON, pretty-formatted. Subcommands
            // return whatever they want here; the standard shape is
            // `{ "ok": true, ... }`.
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()));
            ExitCode::from(0)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> String {
    r#"tron-wallet — key + transaction CLI

Usage:
  tron-wallet keygen   [--out FILE] [--password PW] [--light]
                       [--mnemonic [PHRASE] [--hd-path PATH] [--hd-passphrase PW]]
  tron-wallet address  (--priv HEX | --keystore FILE [--password PW])
  tron-wallet sign     --keystore FILE --tx HEX [--password PW]
  tron-wallet send     --keystore FILE --tx HEX --rpc URL [--password PW]
  tron-wallet keystore list   --dir DIR
  tron-wallet keystore new    --dir DIR [--password PW] [--light]
                              [--mnemonic [PHRASE] [--hd-path PATH] [--hd-passphrase PW]]
  tron-wallet keystore import --dir DIR (--priv HEX | --mnemonic PHRASE)
                              [--password PW] [--light] [--hd-path PATH]
  tron-wallet keystore update --keystore FILE --new-password NEW
                              [--password OLD] [--light]

Password discovery (in order): --password PW, env TRON_WALLET_PASSWORD, then
interactive prompt when stdin is a TTY.

Mnemonic mode:
  --mnemonic            generate a new 12-word BIP-39 phrase and derive a key
                        at the standard TRON path m/44'/195'/0'/0/0
  --mnemonic "PHRASE"   import an existing 12/24-word phrase instead
  --hd-path PATH        override the default derivation path (TRON's coin
                        type is 195; e.g. m/44'/195'/2'/0/5)
  --hd-passphrase PW    BIP-39 25th-word passphrase (default empty)
"#
    .to_string()
}

fn cmd_keygen(args: &[String]) -> Result<serde_json::Value, String> {
    use tron_wallet::{hd, mnemonic};

    let out = arg_value(args, "--out");
    let light = args.iter().any(|a| a == "--light");
    let password = resolve_password(args)?;
    let use_mnemonic = args.iter().any(|a| a == "--mnemonic");

    let (priv_key, mnemonic_phrase, derivation_path) = if use_mnemonic {
        // `--mnemonic [PHRASE]` — value-or-flag-only. If the very next
        // arg after `--mnemonic` doesn't start with `--`, treat it as
        // a phrase to import; otherwise generate a fresh phrase.
        let imported = arg_value_following(args, "--mnemonic");
        let phrase = match imported {
            Some(p) => {
                mnemonic::validate(&p).map_err(|e| format!("--mnemonic: {e}"))?;
                p
            }
            None => mnemonic::generate(mnemonic::WordCount::Twelve)
                .map_err(|e| format!("generate mnemonic: {e}"))?,
        };
        let passphrase = arg_value(args, "--hd-passphrase").unwrap_or_default();
        let seed =
            mnemonic::to_seed(&phrase, &passphrase).map_err(|e| format!("seed: {e}"))?;
        let path = arg_value(args, "--hd-path").unwrap_or_else(|| hd::tron_default_path(0, 0));
        let sk = hd::derive_from_seed(&seed, &path).map_err(|e| format!("derive: {e}"))?;
        (sk, Some(phrase), Some(path))
    } else {
        let sk = generate_private_key().map_err(|e| e.to_string())?;
        (sk, None, None)
    };

    let addr = address_from_private(&priv_key).map_err(|e| e.to_string())?;
    let b58 = address_to_base58(&addr);

    let mut response = json!({
        "ok": true,
        "address": b58,
        "addressHex": format!("0x{}", hex::encode(addr.as_bytes())),
        "privateKey": format!("0x{}", hex::encode(priv_key)),
    });
    if let Some(phrase) = &mnemonic_phrase {
        response["mnemonic"] = json!(phrase);
    }
    if let Some(path) = &derivation_path {
        response["hdPath"] = json!(path);
    }

    if let Some(out_path) = out {
        let pw = password
            .as_deref()
            .ok_or_else(|| "writing a keystore requires --password or TRON_WALLET_PASSWORD".to_string())?;
        let n_log2 = if light { 12 } else { 18 };
        let ks = Keystore::create(&priv_key, pw, &b58, n_log2).map_err(|e| e.to_string())?;
        let path = PathBuf::from(out_path);
        ks.save_to_file(&path).map_err(|e| e.to_string())?;
        response["keystore"] = json!(path.display().to_string());
        // Don't leak the private key in the response when we wrote a
        // keystore — the user already saved it encrypted. Same for
        // mnemonic: writing it alongside an encrypted key defeats the
        // purpose of encrypting.
        response.as_object_mut().unwrap().remove("privateKey");
        response.as_object_mut().unwrap().remove("mnemonic");
    }
    Ok(response)
}

fn cmd_address(args: &[String]) -> Result<serde_json::Value, String> {
    if let Some(priv_hex) = arg_value(args, "--priv") {
        let priv_key = parse_priv(&priv_hex)?;
        let addr = address_from_private(&priv_key).map_err(|e| e.to_string())?;
        return Ok(json!({
            "address": address_to_base58(&addr),
            "addressHex": format!("0x{}", hex::encode(addr.as_bytes())),
        }));
    }
    if let Some(keystore_path) = arg_value(args, "--keystore") {
        let pw = resolve_password(args)?
            .ok_or_else(|| "no password (try --password or TRON_WALLET_PASSWORD)".to_string())?;
        let ks = Keystore::load_from_file(&PathBuf::from(keystore_path))
            .map_err(|e| e.to_string())?;
        let priv_key = ks.decrypt(&pw).map_err(|e| e.to_string())?;
        let addr = address_from_private(&priv_key).map_err(|e| e.to_string())?;
        // Compare against what the keystore claims — surfaces tampering.
        let derived_b58 = address_to_base58(&addr);
        return Ok(json!({
            "address": derived_b58,
            "addressHex": format!("0x{}", hex::encode(addr.as_bytes())),
            "keystoreAddress": ks.address,
            "addressMatch": derived_b58 == ks.address,
        }));
    }
    Err("address: need --priv HEX or --keystore FILE".into())
}

fn cmd_sign(args: &[String]) -> Result<serde_json::Value, String> {
    let keystore_path = arg_value(args, "--keystore")
        .ok_or_else(|| "sign: --keystore FILE required".to_string())?;
    let tx_hex = arg_value(args, "--tx").ok_or_else(|| "sign: --tx HEX required".to_string())?;
    let pw = resolve_password(args)?
        .ok_or_else(|| "no password (try --password or TRON_WALLET_PASSWORD)".to_string())?;

    let ks = Keystore::load_from_file(&PathBuf::from(keystore_path)).map_err(|e| e.to_string())?;
    let priv_key = ks.decrypt(&pw).map_err(|e| e.to_string())?;
    let tx_bytes = parse_hex(&tx_hex)?;
    let signed = sign_transaction_bytes(&tx_bytes, &priv_key).map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "signedHex": format!("0x{}", hex::encode(signed)),
    }))
}

async fn cmd_send(args: &[String]) -> Result<serde_json::Value, String> {
    let keystore_path = arg_value(args, "--keystore")
        .ok_or_else(|| "send: --keystore FILE required".to_string())?;
    let tx_hex = arg_value(args, "--tx").ok_or_else(|| "send: --tx HEX required".to_string())?;
    let rpc = arg_value(args, "--rpc").ok_or_else(|| "send: --rpc URL required".to_string())?;
    let pw = resolve_password(args)?
        .ok_or_else(|| "no password (try --password or TRON_WALLET_PASSWORD)".to_string())?;

    let ks = Keystore::load_from_file(&PathBuf::from(keystore_path)).map_err(|e| e.to_string())?;
    let priv_key = ks.decrypt(&pw).map_err(|e| e.to_string())?;
    let tx_bytes = parse_hex(&tx_hex)?;
    let signed = sign_transaction_bytes(&tx_bytes, &priv_key).map_err(|e| e.to_string())?;
    let response = broadcast_signed_tx(&rpc, &signed)
        .await
        .map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "signedHex": format!("0x{}", hex::encode(&signed)),
        "response": response,
    }))
}

// =============================================================================
// keystore <sub> — multi-keystore directory management
// =============================================================================

fn cmd_keystore(args: &[String]) -> Result<serde_json::Value, String> {
    let sub = args
        .first()
        .ok_or_else(|| "keystore: subcommand required (list | new | import | update)".to_string())?;
    let rest = &args[1..];
    match sub.as_str() {
        "list" => keystore_list(rest),
        "new" => keystore_new(rest),
        "import" => keystore_import(rest),
        "update" => keystore_update(rest),
        other => Err(format!("keystore: unknown subcommand '{other}'")),
    }
}

/// `keystore list --dir DIR` — enumerate every v3 keystore file in
/// `DIR` and report the address each one is encrypted for.
fn keystore_list(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = arg_value(args, "--dir")
        .ok_or_else(|| "keystore list: --dir DIR required".to_string())?;
    let dir_path = PathBuf::from(&dir);
    if !dir_path.is_dir() {
        return Err(format!("not a directory: {dir}"));
    }
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let read = std::fs::read_dir(&dir_path).map_err(|e| format!("read dir: {e}"))?;
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        // Reads metadata only — no decryption attempted (keystore list
        // doesn't ask for passwords). The address field is plaintext
        // in the v3 JSON shape.
        match Keystore::load_from_file(&path) {
            Ok(ks) => entries.push(json!({
                "file": path.display().to_string(),
                "address": ks.address,
                "id": ks.id,
            })),
            Err(e) => entries.push(json!({
                "file": path.display().to_string(),
                "error": format!("{e}"),
            })),
        }
    }
    entries.sort_by(|a, b| {
        a["address"].as_str().unwrap_or("").cmp(b["address"].as_str().unwrap_or(""))
    });
    Ok(json!({
        "ok": true,
        "dir": dir_path.display().to_string(),
        "count": entries.len(),
        "keystores": entries,
    }))
}

/// `keystore new --dir DIR --password PW [--mnemonic [PHRASE]]` —
/// generate a fresh key (optionally via mnemonic) and write it as a
/// keystore file named after its address.
fn keystore_new(args: &[String]) -> Result<serde_json::Value, String> {
    let dir = arg_value(args, "--dir")
        .ok_or_else(|| "keystore new: --dir DIR required".to_string())?;
    let dir_path = PathBuf::from(&dir);
    std::fs::create_dir_all(&dir_path).map_err(|e| format!("create dir: {e}"))?;

    // Delegate the actual key generation to keygen with `--out`
    // synthesised from the address. We can't know the address until
    // after generation, so do it in two steps: generate the key in
    // memory, then write the keystore at `<dir>/<address>.json`.
    let mut keygen_args: Vec<String> = args.to_vec();
    // Strip --dir so cmd_keygen doesn't get confused (it accepts --out
    // not --dir).
    strip_flag_and_value(&mut keygen_args, "--dir");
    // Force keygen to NOT write a keystore yet — we want the
    // privateKey back so we can name the file.
    strip_flag_and_value(&mut keygen_args, "--out");

    let gen_result = cmd_keygen(&keygen_args)?;
    let priv_hex = gen_result["privateKey"]
        .as_str()
        .ok_or_else(|| "keygen returned no privateKey".to_string())?;
    let address = gen_result["address"]
        .as_str()
        .ok_or_else(|| "keygen returned no address".to_string())?;
    let priv_bytes = parse_priv(priv_hex.strip_prefix("0x").unwrap_or(priv_hex))?;

    let pw = resolve_password(args)?
        .ok_or_else(|| "no password (try --password or TRON_WALLET_PASSWORD)".to_string())?;
    let light = args.iter().any(|a| a == "--light");
    let n_log2 = if light { 12 } else { 18 };
    let ks = Keystore::create(&priv_bytes, &pw, address, n_log2)
        .map_err(|e| e.to_string())?;

    let file = dir_path.join(format!("{address}.json"));
    if file.exists() {
        return Err(format!("destination already exists: {}", file.display()));
    }
    ks.save_to_file(&file).map_err(|e| e.to_string())?;

    let mut response = json!({
        "ok": true,
        "address": address,
        "keystore": file.display().to_string(),
    });
    if let Some(mnemonic) = gen_result.get("mnemonic") {
        // Echo the mnemonic ONCE on stdout so the user can record it.
        // After this they'll need it to recover; we never store it.
        response["mnemonic"] = mnemonic.clone();
    }
    if let Some(p) = gen_result.get("hdPath") {
        response["hdPath"] = p.clone();
    }
    Ok(response)
}

/// `keystore import --dir DIR (--priv HEX | --mnemonic PHRASE) --password PW` —
/// take an existing private key (or mnemonic) and write an encrypted
/// keystore file named after the derived address.
fn keystore_import(args: &[String]) -> Result<serde_json::Value, String> {
    use tron_wallet::{hd, mnemonic};

    let dir = arg_value(args, "--dir")
        .ok_or_else(|| "keystore import: --dir DIR required".to_string())?;
    let dir_path = PathBuf::from(&dir);
    std::fs::create_dir_all(&dir_path).map_err(|e| format!("create dir: {e}"))?;

    let priv_bytes = if let Some(priv_hex) = arg_value(args, "--priv") {
        parse_priv(&priv_hex)?
    } else if let Some(phrase) = arg_value(args, "--mnemonic") {
        mnemonic::validate(&phrase).map_err(|e| format!("--mnemonic: {e}"))?;
        let passphrase = arg_value(args, "--hd-passphrase").unwrap_or_default();
        let seed = mnemonic::to_seed(&phrase, &passphrase).map_err(|e| format!("seed: {e}"))?;
        let path = arg_value(args, "--hd-path").unwrap_or_else(|| hd::tron_default_path(0, 0));
        hd::derive_from_seed(&seed, &path).map_err(|e| format!("derive: {e}"))?
    } else {
        return Err("keystore import: --priv HEX or --mnemonic PHRASE required".into());
    };

    let addr = address_from_private(&priv_bytes).map_err(|e| e.to_string())?;
    let b58 = address_to_base58(&addr);
    let pw = resolve_password(args)?
        .ok_or_else(|| "no password (try --password or TRON_WALLET_PASSWORD)".to_string())?;
    let light = args.iter().any(|a| a == "--light");
    let n_log2 = if light { 12 } else { 18 };
    let ks =
        Keystore::create(&priv_bytes, &pw, &b58, n_log2).map_err(|e| e.to_string())?;

    let file = dir_path.join(format!("{b58}.json"));
    if file.exists() {
        return Err(format!("destination already exists: {}", file.display()));
    }
    ks.save_to_file(&file).map_err(|e| e.to_string())?;
    Ok(json!({
        "ok": true,
        "address": b58,
        "keystore": file.display().to_string(),
    }))
}

/// `keystore update --keystore FILE --password OLD --new-password NEW` —
/// re-encrypt an existing keystore under a new password. The file is
/// replaced atomically (write `.tmp`, rename).
fn keystore_update(args: &[String]) -> Result<serde_json::Value, String> {
    let file = arg_value(args, "--keystore")
        .ok_or_else(|| "keystore update: --keystore FILE required".to_string())?;
    let new_pw = arg_value(args, "--new-password")
        .ok_or_else(|| "keystore update: --new-password NEW required".to_string())?;
    let path = PathBuf::from(&file);
    let old_pw = resolve_password(args)?
        .ok_or_else(|| "no old password (try --password or TRON_WALLET_PASSWORD)".to_string())?;
    let light = args.iter().any(|a| a == "--light");
    let n_log2 = if light { 12 } else { 18 };

    let ks = Keystore::load_from_file(&path).map_err(|e| e.to_string())?;
    let priv_bytes = ks.decrypt(&old_pw).map_err(|e| e.to_string())?;
    let re_encrypted = Keystore::create(&priv_bytes, &new_pw, &ks.address, n_log2)
        .map_err(|e| e.to_string())?;

    // Write to .tmp then rename — never leaves a half-written file
    // that locks the user out.
    let mut tmp_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    tmp_name.push_str(".tmp");
    let tmp = path.with_file_name(tmp_name);
    re_encrypted.save_to_file(&tmp).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;

    Ok(json!({
        "ok": true,
        "keystore": path.display().to_string(),
        "address": ks.address,
    }))
}

/// Remove `--flag value` and `--flag=value` forms from `args` in place.
fn strip_flag_and_value(args: &mut Vec<String>, flag: &str) {
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            args.remove(i);
            if i < args.len() {
                args.remove(i);
            }
            continue;
        }
        if args[i].starts_with(&format!("{flag}=")) {
            args.remove(i);
            continue;
        }
        i += 1;
    }
}

// ----- arg helpers ------------------------------------------------------

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().cloned();
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Like [`arg_value`] but the flag is also valid as a bare presence
/// (`--mnemonic` with no value following). Returns `Some(value)` if a
/// non-flag token follows, `None` if the flag is bare or absent.
fn arg_value_following(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(a) = iter.next() {
        if a == flag {
            return iter.next().and_then(|next| {
                if next.starts_with("--") {
                    None
                } else {
                    Some(next.clone())
                }
            });
        }
        if let Some(rest) = a.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

fn resolve_password(args: &[String]) -> Result<Option<String>, String> {
    if let Some(pw) = arg_value(args, "--password") {
        return Ok(Some(pw));
    }
    if let Ok(pw) = std::env::var("TRON_WALLET_PASSWORD") {
        return Ok(Some(pw));
    }
    // Interactive fallback — only when stdin is a TTY. In a pipe or
    // CI context, return None so the caller's error path fires with
    // its "--password or TRON_WALLET_PASSWORD" message instead of
    // hanging waiting for input that will never arrive.
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        match rpassword::prompt_password("Password: ") {
            Ok(pw) if !pw.is_empty() => return Ok(Some(pw)),
            Ok(_) => return Ok(None),
            Err(e) => return Err(format!("reading password: {e}")),
        }
    }
    Ok(None)
}

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

fn parse_priv(s: &str) -> Result<[u8; 32], String> {
    let v = parse_hex(s)?;
    if v.len() != 32 {
        return Err(format!("private key must be 32 bytes; got {}", v.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}
