//! End-to-end tests for the data-safety workflows: identity backup / restore
//! and one-step `ks sync`. These exercise the exact paths a user relies on to
//! avoid losing their key and to share a store across devices.
#![allow(
    unused_crate_dependencies,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "integration test harness: it only links serde_json; panicking JSON indexing, terse asserts, top-level #[test] fns, and expect/unwrap on failure are intentional"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PASS: &str = "integration-pass-123456";

fn unique_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ks-md-it-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Runs `ks` against `dir` with a fixed passphrase and a deterministic git
/// author, so commits made by `ks sync` succeed even on a machine with no
/// global git identity configured.
fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    use std::io::Write as _;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ks"));
    cmd.args(args)
        .env("KS_DIR", dir)
        .env("KS_PASSPHRASE", PASS)
        .env("GIT_AUTHOR_NAME", "ks test")
        .env("GIT_AUTHOR_EMAIL", "ks@example.com")
        .env("GIT_COMMITTER_NAME", "ks test")
        .env("GIT_COMMITTER_EMAIL", "ks@example.com")
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
        "command {args:?} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("stdout is valid JSON")
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
fn identity_export_import_bootstraps_new_device() {
    // Device A: a store with one secret.
    let a = unique_dir();
    let init = json(&a, &["--json", "init"], None);
    let public = init["public_key"].as_str().unwrap().to_owned();
    json(
        &a,
        &["--json", "insert", "svc/token", "--multiline"],
        Some(b"ghp_xxx\nuser: alice\n"),
    );

    // Back up the (still passphrase-protected) identity to a file.
    let backup = a.join("identity-backup.age");
    let exported = json(
        &a,
        &[
            "--json",
            "identity",
            "export",
            "--out",
            backup.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(exported["exported"], backup.to_str().unwrap());
    assert!(backup.exists());

    // Device B: a fresh location. Restore the identity from the backup, then
    // bring the store across the way git would.
    let b = unique_dir();
    let imported = json(
        &b,
        &["--json", "identity", "import", backup.to_str().unwrap()],
        None,
    );
    assert_eq!(imported["public_key"], public);
    copy_dir(&a.join("store"), &b.join("store"));

    // Device B can read a secret it never created.
    let shown = json(&b, &["--json", "show", "svc/token"], None);
    assert_eq!(shown["value"], "ghp_xxx");
    assert_eq!(shown["fields"]["user"], "alice");
}

#[test]
fn identity_armored_export_roundtrips_via_stdin() {
    let a = unique_dir();
    let init = json(&a, &["--json", "init"], None);
    let public = init["public_key"].as_str().unwrap().to_owned();

    // Export as ASCII armor to stdout, then import it on a fresh device via stdin.
    let armored = json(&a, &["--json", "identity", "export", "--armor"], None);
    let text = armored["identity"].as_str().unwrap().to_owned();
    assert!(text.contains("BEGIN AGE ENCRYPTED FILE"));

    let b = unique_dir();
    let imported = json(&b, &["--json", "identity", "import"], Some(text.as_bytes()));
    assert_eq!(imported["public_key"], public);
}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_in(cwd: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "ks test")
        .env("GIT_AUTHOR_EMAIL", "ks@example.com")
        .env("GIT_COMMITTER_NAME", "ks test")
        .env("GIT_COMMITTER_EMAIL", "ks@example.com")
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn sync_roundtrips_between_clones() {
    if !git_available() {
        eprintln!("skipping sync_roundtrips_between_clones: git is not installed");
        return;
    }

    // A bare repository acts as the shared remote. `--initial-branch=main`
    // makes its HEAD point at `main`, so a later clone checks out a working tree
    // instead of warning about a dangling HEAD and leaving it empty.
    let remote = unique_dir().join("remote.git");
    git_in(
        Path::new("."),
        &[
            "init",
            "--bare",
            "--initial-branch=main",
            remote.to_str().unwrap(),
        ],
    );

    // Device A: init a git-backed store, publish the initial commit upstream.
    let a = unique_dir();
    json(&a, &["--json", "init", "--git"], None);
    let store_a = a.join("store");
    git_in(&store_a, &["add", "-A"]);
    git_in(&store_a, &["commit", "-m", "init store"]);
    git_in(
        &store_a,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git_in(&store_a, &["push", "-u", "origin", "main"]);

    // Add a secret and sync it in one step.
    json(
        &a,
        &["--json", "insert", "svc/token", "--multiline"],
        Some(b"s3cr3t\n"),
    );
    let synced = json(&a, &["--json", "sync", "-m", "add token"], None);
    assert_eq!(synced["synced"], serde_json::Value::Bool(true));

    // Device B: clone the remote and restore the identity, then read the secret.
    let backup = a.join("id.age");
    json(
        &a,
        &[
            "--json",
            "identity",
            "export",
            "--out",
            backup.to_str().unwrap(),
        ],
        None,
    );
    let b = unique_dir();
    git_in(
        Path::new("."),
        &[
            "clone",
            "-b",
            "main",
            remote.to_str().unwrap(),
            b.join("store").to_str().unwrap(),
        ],
    );
    json(
        &b,
        &["--json", "identity", "import", backup.to_str().unwrap()],
        None,
    );

    let shown = json(&b, &["--json", "show", "svc/token"], None);
    assert_eq!(shown["value"], "s3cr3t");
}
