//! Embeds the git short-SHA (with a `-dirty` marker for an uncommitted tree)
//! into the binary as `GOBLIN_GIT_SHA`, surfaced on the startup `🧌 build:` line.
//! Falls back to `unknown` outside a git checkout (e.g. a packaged source tree).

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn main() {
    let mut sha = git(&["rev-parse", "--short=9", "HEAD"]).unwrap_or_else(|| "unknown".to_string());
    // Mark a build from an uncommitted working tree so a quick local build is
    // never mistaken for the committed revision during divergence triage.
    if git(&["status", "--porcelain"]).map(|s| !s.is_empty()).unwrap_or(false) {
        sha.push_str("-dirty");
    }
    println!("cargo:rustc-env=GOBLIN_GIT_SHA={sha}");

    // Rebuild the version line when HEAD moves (best-effort; harmless if absent).
    for p in ["../../.git/HEAD", "../../.git/index"] {
        println!("cargo:rerun-if-changed={p}");
    }
}
