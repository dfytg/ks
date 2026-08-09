//! End-to-end security and feature matrix against the real `ks` binary.
//!
//! Covers agent JSON contract paths, integrity (P1/P2), identity lifecycle,
//! recipients rotation, doctor/repair, and adversarial filesystem swaps.
#![allow(
    unused_crate_dependencies,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test harness: serde_json only; panic on assert is intentional"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PASS: &str = "e2e-security-pass-987654";

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ks-e2e-{}-{}-{seq}", std::process::id(), nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ks"));
    cmd.args(args)
        .env("KS_DIR", dir)
        .env("KS_PASSPHRASE", PASS)
        .env_remove("KS_STRICT_HARDEN")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn ks");
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(bytes)
            .expect("write stdin");
    }
    child.wait_with_output().expect("wait ks")
}

fn json(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> serde_json::Value {
    let out = run(dir, args, stdin);
    assert!(
        out.status.success(),
        "command {args:?} failed (status {:?}):\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout JSON")
}

fn json_err(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> serde_json::Value {
    let out = run(dir, args, stdin);
    assert!(
        !out.status.success(),
        "expected failure for {args:?}, got success: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).expect("error JSON")
}

fn store_secret_path(dir: &Path, logical: &str) -> PathBuf {
    let mut p = dir.join("store");
    for seg in logical.split('/') {
        p = p.join(seg);
    }
    p.set_extension("age");
    p
}

#[test]
fn full_lifecycle_matrix() {
    let dir = unique_dir();
    let init = json(&dir, &["--json", "init"], None);
    assert!(init["public_key"].as_str().unwrap().starts_with("age1"));

    // insert text + fields
    json(
        &dir,
        &["--json", "insert", "app/token", "--multiline"],
        Some(b"secret-value\nuser: bob\nnote: test\n"),
    );
    let shown = json(&dir, &["--json", "show", "app/token"], None);
    assert_eq!(shown["value"], "secret-value");
    assert_eq!(shown["fields"]["user"], "bob");
    assert_eq!(
        json(&dir, &["--json", "show", "app/token", "-f", "user"], None)["value"],
        "bob"
    );
    let meta = json(&dir, &["--json", "show", "app/token", "--meta"], None);
    assert!(
        meta["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "user")
    );

    // gen store
    let generated = json(
        &dir,
        &["--json", "gen", "app/random", "-l", "24", "-s", "hex"],
        None,
    );
    assert_eq!(generated["length"], 24);
    assert_eq!(generated["value"].as_str().unwrap().len(), 24);

    // binary
    json(
        &dir,
        &["--json", "insert", "bin/data", "--binary"],
        Some(&[0u8, 1, 2, 255, b'\n', 0]),
    );
    let bin = json(&dir, &["--json", "show", "bin/data"], None);
    assert_eq!(bin["kind"], "binary");
    assert!(bin["base64"].as_str().unwrap().len() > 4);

    // ls / grep
    let ls = json(&dir, &["--json", "ls"], None);
    let secrets = ls["secrets"].as_array().unwrap();
    assert!(secrets.iter().any(|s| s == "app/token"));
    let grep = json(&dir, &["--json", "grep", "token"], None);
    assert!(
        grep["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "app/token")
    );
    let grepv = json(&dir, &["--json", "grep", "bob", "--values"], None);
    assert!(
        grepv["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "app/token")
    );

    // mv / cp
    json(&dir, &["--json", "cp", "app/token", "app/token-copy"], None);
    json(
        &dir,
        &["--json", "mv", "app/token-copy", "app/token-moved"],
        None,
    );
    assert_eq!(
        json(&dir, &["--json", "show", "app/token-moved"], None)["value"],
        "secret-value"
    );
    let err = json_err(&dir, &["--json", "show", "app/token-copy"], None);
    assert!(err["error"].as_str().unwrap().contains("not found"));

    // overwrite force
    json(
        &dir,
        &["--json", "insert", "app/token", "--force", "--multiline"],
        Some(b"rotated\n"),
    );
    assert_eq!(
        json(&dir, &["--json", "show", "app/token"], None)["value"],
        "rotated"
    );

    // rm without force fails in json
    let _ = json_err(&dir, &["--json", "rm", "app/random"], None);
    json(&dir, &["--json", "rm", "app/random", "--force"], None);

    // identity export
    let export = json(&dir, &["--json", "identity", "export", "--armor"], None);
    assert!(
        export["identity"]
            .as_str()
            .unwrap()
            .contains("BEGIN AGE ENCRYPTED FILE")
    );

    // doctor
    let doc = json(&dir, &["--json", "doctor"], None);
    assert_eq!(doc["ok"], serde_json::Value::Bool(true));
    assert_eq!(doc["failures"], 0);

    // recipients list contains own key
    let recips = json(&dir, &["--json", "recipients", "ls"], None);
    assert!(!recips["recipients"].as_array().unwrap().is_empty());
}

#[test]
fn path_swap_detected_as_tampered() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "x/a", "--multiline"],
        Some(b"aaa\n"),
    );
    json(
        &dir,
        &["--json", "insert", "x/b", "--multiline"],
        Some(b"bbb\n"),
    );

    let pa = store_secret_path(&dir, "x/a");
    let pb = store_secret_path(&dir, "x/b");
    let tmp = dir.join("store/swap.tmp");
    std::fs::rename(&pa, &tmp).unwrap();
    std::fs::rename(&pb, &pa).unwrap();
    std::fs::rename(&tmp, &pb).unwrap();

    let err = json_err(&dir, &["--json", "show", "x/a"], None);
    let msg = err["error"].as_str().unwrap();
    assert!(
        msg.contains("integrity")
            || msg.contains("bound path")
            || msg.contains("Tampered")
            || msg.contains("tamper"),
        "unexpected error: {msg}"
    );
}

#[test]
fn older_ciphertext_under_newer_index_is_rejected() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "p/key", "--multiline"],
        Some(b"old\n"),
    );
    let path = store_secret_path(&dir, "p/key");
    let old_ct = std::fs::read(&path).unwrap();
    json(
        &dir,
        &["--json", "insert", "p/key", "--force", "--multiline"],
        Some(b"new\n"),
    );
    std::fs::write(&path, old_ct).unwrap();

    let err = json_err(&dir, &["--json", "show", "p/key"], None);
    let msg = err["error"].as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("integrity") || msg.contains("generation") || msg.contains("older"),
        "unexpected: {msg}"
    );

    // repair lowers floor → local get works (single device)
    let repaired = json(&dir, &["--json", "doctor", "--repair-generations"], None);
    assert!(
        repaired["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("repaired")),
        "expected repair note: {repaired}"
    );
    assert_eq!(
        json(&dir, &["--json", "show", "p/key"], None)["value"],
        "old"
    );
}

#[test]
fn set_at_high_index_without_repair_bumps_generation() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    for v in [b"a\n".as_slice(), b"b\n", b"c\n"] {
        json(
            &dir,
            &["--json", "insert", "g/path", "--force", "--multiline"],
            Some(v),
        );
    }
    // Plant stale ciphertext under a high index (simulate lagging device).
    let path = store_secret_path(&dir, "g/path");
    let stale_ct = std::fs::read(&path).unwrap();
    json(
        &dir,
        &["--json", "insert", "g/path", "--force", "--multiline"],
        Some(b"newer\n"),
    );
    let high_index = std::fs::read_to_string(dir.join("store/.ks-generations")).unwrap();
    assert!(
        high_index.contains("g/path"),
        "index should track path: {high_index}"
    );
    // Restore older ciphertext; index still high → get fails (P1).
    std::fs::write(&path, &stale_ct).unwrap();
    let _ = json_err(&dir, &["--json", "show", "g/path"], None);
    // Durable multi-device rewrite: set while index is still high (H+1), no repair.
    json(
        &dir,
        &["--json", "insert", "g/path", "--force", "--multiline"],
        Some(b"durable\n"),
    );
    assert_eq!(
        json(&dir, &["--json", "show", "g/path"], None)["value"],
        "durable"
    );
    let after = std::fs::read_to_string(dir.join("store/.ks-generations")).unwrap();
    // Generation must have advanced past the previous high floor.
    let generation = after
        .lines()
        .find(|l| l.starts_with("g/path "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|g| g.parse::<u64>().ok())
        .expect("gen line");
    assert!(
        generation >= 5,
        "expected H+1 style gen, got {generation} in:\n{after}"
    );
}

#[test]
fn recipients_add_reencrypts() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "k", "--multiline"],
        Some(b"v\n"),
    );

    // Generate a second identity via a temp store and steal its public key.
    let other = unique_dir();
    let oinit = json(&other, &["--json", "init"], None);
    let pubkey = oinit["public_key"].as_str().unwrap();

    let added = json(&dir, &["--json", "recipients", "add", pubkey], None);
    assert_eq!(added["reencrypted"], 1);

    // Import other identity into a clone of the store ciphertext.
    let backup = other.join("id.age");
    json(
        &other,
        &[
            "--json",
            "identity",
            "export",
            "--out",
            backup.to_str().unwrap(),
        ],
        None,
    );
    let reader = unique_dir();
    json(
        &reader,
        &["--json", "identity", "import", backup.to_str().unwrap()],
        None,
    );
    // Copy store files only (recipients already include both keys).
    copy_dir(&dir.join("store"), &reader.join("store"));
    assert_eq!(json(&reader, &["--json", "show", "k"], None)["value"], "v");
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

#[test]
fn wrong_passphrase_fails() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "s", "--multiline"],
        Some(b"x\n"),
    );

    let out = Command::new(env!("CARGO_BIN_EXE_ks"))
        .args(["--json", "show", "s"])
        .env("KS_DIR", &dir)
        .env("KS_PASSPHRASE", "wrong-password-not-the-real-one")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let msg = err["error"].as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("passphrase") || msg.contains("incorrect") || msg.contains("decrypt"),
        "unexpected: {msg}"
    );
}

#[test]
fn missing_passphrase_in_json_fails() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    let out = Command::new(env!("CARGO_BIN_EXE_ks"))
        .args(["--json", "show", "anything"])
        .env("KS_DIR", &dir)
        .env_remove("KS_PASSPHRASE")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(err["error"].as_str().unwrap().contains("KS_PASSPHRASE"));
}

#[test]
fn invalid_paths_rejected() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    for bad in ["../escape", "/abs", "a//b", "a/./b", "CON", ""] {
        let out = run(&dir, &["--json", "insert", bad], Some(b"x\n"));
        assert!(!out.status.success(), "path `{bad}` should be rejected");
    }
}

#[test]
fn run_injects_env() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "db/url", "--multiline"],
        Some(b"postgres://local\n"),
    );
    // `ks run` is not fully --json for child stdout; check exit + that child sees env.
    // Use a tiny shell that fails if env missing.
    let out = Command::new(env!("CARGO_BIN_EXE_ks"))
        .args([
            "run",
            "-e",
            "db/url=DATABASE_URL",
            "--",
            "sh",
            "-c",
            "test \"$DATABASE_URL\" = 'postgres://local'",
        ])
        .env("KS_DIR", &dir)
        .env("KS_PASSPHRASE", PASS)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "run inject failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn doctor_repair_mixed_store_skips_corrupt() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "good", "--multiline"],
        Some(b"ok\n"),
    );
    json(
        &dir,
        &["--json", "insert", "bad", "--multiline"],
        Some(b"ok\n"),
    );
    // Create lag on good.
    let good_path = store_secret_path(&dir, "good");
    let good_ct = std::fs::read(&good_path).unwrap();
    json(
        &dir,
        &["--json", "insert", "good", "--force", "--multiline"],
        Some(b"newer\n"),
    );
    std::fs::write(&good_path, good_ct).unwrap();
    // Corrupt bad.
    std::fs::write(store_secret_path(&dir, "bad"), b"not-an-age-file").unwrap();

    // Doctor may exit non-zero because corrupt `bad` fails sample decrypt — still
    // must repair `good` and report the skip.
    let out = run(&dir, &["--json", "doctor", "--repair-generations"], None);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("doctor json");
    let notes = doc["notes"].as_array().expect("notes");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("repaired")),
        "missing repair note: {doc}"
    );
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("skipped unreadable")),
        "missing skip note: {doc}"
    );
    // good should be readable again (stale repaired to older ciphertext gen)
    assert_eq!(json(&dir, &["--json", "show", "good"], None)["value"], "ok");
    // bad remains unreadable
    let _ = json_err(&dir, &["--json", "show", "bad"], None);
}

#[test]
fn delete_tombstone_allows_reinsert() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    json(
        &dir,
        &["--json", "insert", "t/path", "--multiline"],
        Some(b"1\n"),
    );
    json(
        &dir,
        &["--json", "insert", "t/path", "--force", "--multiline"],
        Some(b"2\n"),
    );
    json(&dir, &["--json", "rm", "t/path", "--force"], None);
    json(
        &dir,
        &["--json", "insert", "t/path", "--multiline"],
        Some(b"3\n"),
    );
    assert_eq!(
        json(&dir, &["--json", "show", "t/path"], None)["value"],
        "3"
    );
}

#[test]
fn double_init_refuses_overwrite() {
    let dir = unique_dir();
    json(&dir, &["--json", "init"], None);
    let err = json_err(&dir, &["--json", "init"], None);
    let msg = err["error"].as_str().unwrap().to_lowercase();
    assert!(
        msg.contains("exist") || msg.contains("already"),
        "unexpected: {msg}"
    );
}
