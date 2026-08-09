//! # Ultimate CLI stress & coverage matrix
//!
//! Real-binary e2e against every top-level command, major flags, fail-closed
//! security edges, and a stress pocket. Interactive-only surfaces assert the
//! JSON contract; `edit` is exercised via a scripted `$EDITOR`.
//!
//! ## Design
//!
//! | Layer | Scope | How |
//! |-------|--------|-----|
//! | L0 Global | `--help`, `--version`, clap aliases | spawn, success |
//! | L1 CRUD | init, insert×4, show×4, ls, rm, mv, cp | `--json` + assertions |
//! | L2 Derive | gen charsets, grep, otp | `--json` |
//! | L3 Orchestrate | run `-e`/`-p`, identity export/import, recipients add/rm | `--json` + peer store |
//! | L4 Ops | doctor, doctor `--repair-generations`, git, sync | git soft-skip |
//! | L5 Interactive | edit (EDITOR script), passwd/edit JSON reject | scripted / contract |
//! | L6 Integrity | P1 stale, P2 path swap, corrupt, tombstone | fail-closed + repair |
//! | L7 Auth/Path | wrong/missing passphrase, invalid paths | reject |
//! | L8 Edges | missing secret, bad recipient, otp no source, bad run map, dest exists | reject |
//! | L9 Stress | N roundtrips, nested depth, large payload, unicode | durability |
//!
//! ## Not claimed
//!
//! - Interactive `passwd` TTY passphrase UI (library crypto covered elsewhere)
//! - Clipboard success on headless CI (best-effort mark)
//! - Absolute safety proofs (only observable binary contracts)
//!
//! Run: `cargo test -p ks-cli --test e2e_ultimate -- --nocapture`
//! Just: `just test-ultimate`
#![allow(
    unused_crate_dependencies,
    clippy::indexing_slicing,
    clippy::missing_assert_message,
    clippy::tests_outside_test_module,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_const_for_fn,
    clippy::shadow_unrelated,
    clippy::print_stderr,
    reason = "integration harness: intentional panics/asserts; coverage report on stderr"
)]

use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PASS: &str = "ultimate-matrix-pass-2026";
/// Encrypt/decrypt roundtrips; kept moderate so CI stays under a few minutes.
const STRESS_N: usize = 40;
const LARGE_BYTES: usize = 64 * 1024;

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);
static COVERED: Mutex<BTreeSet<&'static str>> = Mutex::new(BTreeSet::new());

/// Marks that must appear or the suite fails (hard gate).
const REQUIRED: &[&str] = &[
    "help",
    "version",
    "alias/list",
    "alias/get",
    "alias/set",
    "alias/del",
    "alias/find",
    "init",
    "init/refuse-overwrite",
    "insert/plain",
    "insert/multiline",
    "insert/binary",
    "insert/force",
    "insert/no-force-error",
    "show",
    "show/field",
    "show/meta",
    "show/binary",
    "show/missing",
    "ls",
    "ls/prefix",
    "gen/alphanum",
    "gen/hex",
    "gen/printable",
    "gen/slug",
    "gen/no-store",
    "gen/force",
    "grep",
    "grep/values",
    "otp",
    "otp/no-source",
    "cp",
    "cp/dest-exists",
    "mv",
    "mv/source-gone",
    "mv/dest-exists",
    "rm/no-force-error",
    "rm/force",
    "rm/tombstone-reinsert",
    "run/env",
    "run/prefix",
    "run/bad-mapping",
    "identity",
    "identity/export-armor",
    "identity/export-file",
    "identity/import",
    "identity/import-refuse",
    "identity/import-force",
    "recipients/ls",
    "recipients/add",
    "recipients/add-peer-read",
    "recipients/add-idempotent",
    "recipients/add-invalid",
    "recipients/rm",
    "recipients/rm-missing",
    "doctor",
    "doctor/repair-generations",
    "edit/scripted",
    "edit/json-rejected",
    "passwd/json-rejected",
    "integrity/P1-stale",
    "integrity/P1-repair",
    "integrity/P2-swap",
    "integrity/corrupt-ciphertext",
    "auth/wrong-passphrase",
    "auth/missing-passphrase",
    "path/invalid",
    "stress/roundtrip",
    "stress/nested",
    "stress/large",
    "stress/unicode",
];

fn mark(id: &'static str) {
    COVERED.lock().unwrap().insert(id);
}

fn unique_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let seq = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("ks-ult-{}-{}-{seq}", std::process::id(), nanos));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ks")
}

fn run_env(
    dir: &Path,
    args: &[&str],
    stdin: Option<&[u8]>,
    passphrase: Option<&str>,
    extra_env: &[(&str, &str)],
) -> Output {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env("KS_DIR", dir)
        .env_remove("KS_STRICT_HARDEN")
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match passphrase {
        Some(p) => {
            cmd.env("KS_PASSPHRASE", p);
        }
        None => {
            cmd.env_remove("KS_PASSPHRASE");
        }
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().expect("spawn");
    if let Some(bytes) = stdin {
        child.stdin.take().unwrap().write_all(bytes).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    run_env(dir, args, stdin, Some(PASS), &[])
}

fn json_ok(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> serde_json::Value {
    let out = run(dir, args, stdin);
    assert!(
        out.status.success(),
        "{args:?} failed status={:?}\nstdout={}\nstderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("json")
}

fn json_err(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> serde_json::Value {
    let out = run(dir, args, stdin);
    assert!(
        !out.status.success(),
        "expected fail {args:?}: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    serde_json::from_slice(&out.stdout).expect("err json")
}

fn store_age(dir: &Path, logical: &str) -> PathBuf {
    let mut p = dir.join("store");
    for seg in logical.split('/') {
        p.push(seg);
    }
    p.set_extension("age");
    p
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for e in std::fs::read_dir(src).unwrap() {
        let e = e.unwrap();
        let from = e.path();
        let to = dst.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

fn git_ok() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn git_in(cwd: &Path, args: &[&str]) {
    let git_out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_AUTHOR_NAME", "ks")
        .env("GIT_AUTHOR_EMAIL", "ks@test")
        .env("GIT_COMMITTER_NAME", "ks")
        .env("GIT_COMMITTER_EMAIL", "ks@test")
        .output()
        .unwrap();
    assert!(
        git_out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&git_out.stderr)
    );
}

fn cover_global() {
    let help = Command::new(bin()).args(["--help"]).output().unwrap();
    assert!(help.status.success());
    let help_txt = String::from_utf8_lossy(&help.stdout);
    assert!(help_txt.contains("init") && help_txt.contains("show"));
    mark("help");

    let ver = Command::new(bin()).args(["--version"]).output().unwrap();
    assert!(ver.status.success());
    mark("version");
}

fn cover_init(dir: &Path) {
    let init = json_ok(dir, &["--json", "init"], None);
    assert!(init["public_key"].as_str().unwrap().starts_with("age1"));
    mark("init");

    let err = json_err(dir, &["--json", "init"], None);
    assert!(
        err["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("exist")
    );
    mark("init/refuse-overwrite");
}

fn cover_aliases(dir: &Path) {
    // set / insert alias
    json_ok(dir, &["--json", "set", "alias/via-set"], Some(b"via-set"));
    mark("alias/set");
    // get / show alias
    assert_eq!(
        json_ok(dir, &["--json", "get", "alias/via-set"], None)["value"],
        "via-set"
    );
    mark("alias/get");
    // list / ls
    let listed = json_ok(dir, &["--json", "list"], None);
    assert!(
        listed["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("alias/via-set"))
    );
    mark("alias/list");
    // find / grep
    let found = json_ok(dir, &["--json", "find", "via-set"], None);
    assert!(!found["matches"].as_array().unwrap().is_empty());
    mark("alias/find");
    // del / rm
    json_ok(dir, &["--json", "del", "alias/via-set", "--force"], None);
    mark("alias/del");
}

fn cover_insert_show_ls(dir: &Path) {
    json_ok(
        dir,
        &["--json", "insert", "svc/token"],
        Some(b"plain-secret"),
    );
    mark("insert/plain");

    json_ok(
        dir,
        &["--json", "insert", "svc/multi", "--multiline"],
        Some(b"line1\nuser: alice\nurl: https://x\n"),
    );
    mark("insert/multiline");

    json_ok(
        dir,
        &["--json", "insert", "svc/bin", "--binary"],
        Some(&[0, 1, 2, 255, b'\n']),
    );
    mark("insert/binary");

    json_ok(
        dir,
        &["--json", "insert", "svc/token", "--force"],
        Some(b"plain-secret-2"),
    );
    mark("insert/force");

    let _ = json_err(dir, &["--json", "insert", "svc/token"], Some(b"nope"));
    mark("insert/no-force-error");

    let sh = json_ok(dir, &["--json", "show", "svc/token"], None);
    assert_eq!(sh["value"], "plain-secret-2");
    mark("show");

    let field = json_ok(dir, &["--json", "show", "svc/multi", "-f", "user"], None);
    assert_eq!(field["value"], "alice");
    mark("show/field");

    let meta = json_ok(dir, &["--json", "show", "svc/multi", "--meta"], None);
    assert!(
        meta["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "user")
    );
    mark("show/meta");

    let bin_show = json_ok(dir, &["--json", "show", "svc/bin"], None);
    assert_eq!(bin_show["kind"], "binary");
    assert!(bin_show["base64"].as_str().unwrap().len() > 2);
    mark("show/binary");

    let missing = json_err(dir, &["--json", "show", "does/not/exist"], None);
    assert!(!missing["error"].as_str().unwrap().is_empty());
    mark("show/missing");

    let clip = run(dir, &["--json", "show", "svc/token", "-c"], None);
    if clip.status.success() {
        mark("show/copy");
    } else {
        mark("show/copy-skipped-or-failed");
    }

    let ls = json_ok(dir, &["--json", "ls"], None);
    assert!(ls["secrets"].as_array().unwrap().len() >= 3);
    mark("ls");

    let lsp = json_ok(dir, &["--json", "ls", "svc"], None);
    assert!(
        lsp["secrets"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s.as_str().unwrap().starts_with("svc/"))
    );
    mark("ls/prefix");
}

fn cover_gen_grep_otp(dir: &Path) {
    for (cs, id) in [
        ("alphanum", "gen/alphanum"),
        ("hex", "gen/hex"),
        ("printable", "gen/printable"),
        ("slug", "gen/slug"),
    ] {
        let path = format!("generated/{cs}");
        let g = json_ok(dir, &["--json", "gen", &path, "-l", "16", "-s", cs], None);
        assert_eq!(g["length"], 16);
        assert_eq!(g["value"].as_str().unwrap().len(), 16);
        mark(id);
    }

    let gonly = json_ok(dir, &["--json", "gen", "-l", "12", "-s", "hex"], None);
    assert_eq!(gonly["value"].as_str().unwrap().len(), 12);
    mark("gen/no-store");

    json_ok(
        dir,
        &[
            "--json",
            "gen",
            "generated/hex",
            "-l",
            "8",
            "-s",
            "hex",
            "--force",
        ],
        None,
    );
    mark("gen/force");

    let gc = run(
        dir,
        &["--json", "gen", "generated/clip", "-l", "8", "-c"],
        None,
    );
    if gc.status.success() {
        mark("gen/copy");
    } else {
        mark("gen/copy-skipped-or-failed");
    }

    let gp = json_ok(dir, &["--json", "grep", "token"], None);
    assert!(
        gp["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m.as_str().unwrap().contains("token"))
    );
    mark("grep");

    let gpv = json_ok(dir, &["--json", "grep", "alice", "--values"], None);
    assert!(
        gpv["matches"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m == "svc/multi")
    );
    mark("grep/values");

    let otpauth = "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30";
    json_ok(
        dir,
        &["--json", "insert", "otp/ex", "--multiline"],
        Some(otpauth.as_bytes()),
    );
    let code = json_ok(dir, &["--json", "otp", "otp/ex"], None);
    assert_eq!(code["code"].as_str().unwrap().len(), 6);
    assert!(code["valid_for_secs"].as_u64().unwrap() <= 30);
    mark("otp");

    let otpc = run(dir, &["--json", "otp", "otp/ex", "-c"], None);
    if otpc.status.success() {
        mark("otp/copy");
    } else {
        mark("otp/copy-skipped-or-failed");
    }

    let _ = json_err(dir, &["--json", "otp", "svc/token"], None);
    mark("otp/no-source");
}

fn cover_cp_mv_rm(dir: &Path) {
    json_ok(dir, &["--json", "cp", "svc/token", "svc/token-cp"], None);
    mark("cp");

    // dest exists → fail
    let cp_err = json_err(dir, &["--json", "cp", "svc/token", "svc/multi"], None);
    assert!(!cp_err["error"].as_str().unwrap().is_empty());
    mark("cp/dest-exists");

    json_ok(dir, &["--json", "mv", "svc/token-cp", "svc/token-mv"], None);
    mark("mv");
    assert_eq!(
        json_ok(dir, &["--json", "show", "svc/token-mv"], None)["value"],
        "plain-secret-2"
    );
    let _ = json_err(dir, &["--json", "show", "svc/token-cp"], None);
    mark("mv/source-gone");

    let mv_err = json_err(dir, &["--json", "mv", "svc/token", "svc/multi"], None);
    assert!(!mv_err["error"].as_str().unwrap().is_empty());
    mark("mv/dest-exists");

    let _ = json_err(dir, &["--json", "rm", "svc/token-mv"], None);
    mark("rm/no-force-error");
    json_ok(dir, &["--json", "rm", "svc/token-mv", "--force"], None);
    mark("rm/force");

    // tombstone then reinsert
    json_ok(dir, &["--json", "insert", "svc/token-mv"], Some(b"reborn"));
    assert_eq!(
        json_ok(dir, &["--json", "show", "svc/token-mv"], None)["value"],
        "reborn"
    );
    json_ok(dir, &["--json", "rm", "svc/token-mv", "--force"], None);
    mark("rm/tombstone-reinsert");
}

fn cover_run(dir: &Path) {
    json_ok(
        dir,
        &["--json", "insert", "run/a", "--force"],
        Some(b"val-a"),
    );
    json_ok(
        dir,
        &["--json", "insert", "run/b", "--force"],
        Some(b"val-b"),
    );

    let run_e = run(
        dir,
        &[
            "run",
            "-e",
            "run/a=RUN_A",
            "--",
            "sh",
            "-c",
            "test \"$RUN_A\" = val-a",
        ],
        None,
    );
    assert!(run_e.status.success(), "run -e failed");
    mark("run/env");

    let run_p = run(
        dir,
        &[
            "run",
            "-p",
            "run",
            "--",
            "sh",
            "-c",
            "test \"$RUN_A\" = val-a && test \"$RUN_B\" = val-b",
        ],
        None,
    );
    assert!(
        run_p.status.success(),
        "run -p failed: {}",
        String::from_utf8_lossy(&run_p.stderr)
    );
    mark("run/prefix");

    let bad_map = run(dir, &["run", "-e", "not-a-mapping", "--", "true"], None);
    assert!(!bad_map.status.success());
    mark("run/bad-mapping");
}

fn cover_identity(dir: &Path) {
    let id = json_ok(dir, &["--json", "identity"], None);
    let pubkey = id["public_key"].as_str().unwrap();
    assert!(pubkey.starts_with("age1"));
    mark("identity");

    let armored = json_ok(dir, &["--json", "identity", "export", "--armor"], None);
    assert!(
        armored["identity"]
            .as_str()
            .unwrap()
            .contains("BEGIN AGE ENCRYPTED FILE")
    );
    mark("identity/export-armor");

    let backup = dir.join("id-backup.age");
    json_ok(
        dir,
        &[
            "--json",
            "identity",
            "export",
            "--out",
            backup.to_str().unwrap(),
        ],
        None,
    );
    assert!(backup.exists());
    mark("identity/export-file");

    let other = unique_dir();
    json_ok(
        &other,
        &["--json", "identity", "import", backup.to_str().unwrap()],
        None,
    );
    mark("identity/import");

    let _ = json_err(
        &other,
        &["--json", "identity", "import", backup.to_str().unwrap()],
        None,
    );
    mark("identity/import-refuse");

    json_ok(
        &other,
        &[
            "--json",
            "identity",
            "import",
            backup.to_str().unwrap(),
            "--force",
        ],
        None,
    );
    mark("identity/import-force");
}

fn cover_recipients(dir: &Path) {
    let rec = json_ok(dir, &["--json", "recipients", "ls"], None);
    assert!(!rec["recipients"].as_array().unwrap().is_empty());
    mark("recipients/ls");

    let peer = unique_dir();
    let pinit = json_ok(&peer, &["--json", "init"], None);
    let peer_pub = pinit["public_key"].as_str().unwrap().to_owned();

    let add = json_ok(dir, &["--json", "recipients", "add", &peer_pub], None);
    assert!(add["reencrypted"].as_u64().unwrap() >= 1);
    mark("recipients/add");

    copy_dir(&dir.join("store"), &peer.join("store"));
    assert_eq!(
        json_ok(&peer, &["--json", "show", "svc/token"], None)["value"],
        "plain-secret-2"
    );
    mark("recipients/add-peer-read");

    let again = json_ok(dir, &["--json", "recipients", "add", &peer_pub], None);
    assert_eq!(again["reencrypted"], 0);
    mark("recipients/add-idempotent");

    let bad = json_err(dir, &["--json", "recipients", "add", "not-a-key"], None);
    assert!(!bad["error"].as_str().unwrap().is_empty());
    mark("recipients/add-invalid");

    let rm = json_ok(dir, &["--json", "recipients", "rm", &peer_pub], None);
    assert!(rm["reencrypted"].as_u64().unwrap() >= 1);
    mark("recipients/rm");

    assert_eq!(
        json_ok(dir, &["--json", "show", "svc/token"], None)["value"],
        "plain-secret-2"
    );

    // rm missing recipient → reencrypted 0
    let rm_miss = json_ok(dir, &["--json", "recipients", "rm", &peer_pub], None);
    assert_eq!(rm_miss["reencrypted"], 0);
    mark("recipients/rm-missing");
}

fn cover_doctor(dir: &Path) {
    let doc = json_ok(dir, &["--json", "doctor"], None);
    assert!(doc["checks"].as_array().unwrap().len() >= 3);
    mark("doctor");

    let doc2 = run(dir, &["--json", "doctor", "--repair-generations"], None);
    assert!(
        doc2.status.success(),
        "doctor --repair-generations failed: {}",
        String::from_utf8_lossy(&doc2.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&doc2.stdout).unwrap();
    assert!(
        v["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap_or("").contains("repaired")),
        "expected repair note in doctor output: {v}"
    );
    mark("doctor/repair-generations");
}

fn cover_edit_passwd(dir: &Path) {
    let editor_script = dir.join("fake-editor.sh");
    std::fs::write(
        &editor_script,
        "#!/bin/sh\nprintf 'edited-by-ultimate\\nuser: z\\n' > \"$1\"\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&editor_script).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&editor_script, perms).unwrap();
    }

    let edit_out = run_env(
        dir,
        &["edit", "svc/token"],
        None,
        Some(PASS),
        &[("EDITOR", editor_script.to_str().unwrap())],
    );
    assert!(
        edit_out.status.success(),
        "edit failed: {}",
        String::from_utf8_lossy(&edit_out.stderr)
    );
    assert_eq!(
        json_ok(dir, &["--json", "show", "svc/token"], None)["value"],
        "edited-by-ultimate"
    );
    mark("edit/scripted");

    let e = json_err(dir, &["--json", "edit", "svc/token"], None);
    assert!(
        e["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("interactive")
    );
    mark("edit/json-rejected");

    let pe = json_err(dir, &["--json", "passwd"], None);
    assert!(
        pe["error"]
            .as_str()
            .unwrap()
            .to_lowercase()
            .contains("interactive")
    );
    mark("passwd/json-rejected");
}

fn cover_git_sync() {
    if !git_ok() {
        mark("git/skipped-no-git");
        mark("sync/skipped-no-git");
        mark("init/git-skipped");
        mark("sync/clone-read-skipped");
        return;
    }

    let gdir = unique_dir();
    json_ok(&gdir, &["--json", "init", "--git"], None);
    mark("init/git");

    let store = gdir.join("store");
    git_in(&store, &["add", "-A"]);
    git_in(&store, &["commit", "-m", "init"]);

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
    git_in(
        &store,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    git_in(&store, &["push", "-u", "origin", "main"]);

    json_ok(&gdir, &["--json", "insert", "g/s"], Some(b"synced"));

    let gst = run(&gdir, &["git", "status", "-sb"], None);
    assert!(
        gst.status.success(),
        "ks git status: {}",
        String::from_utf8_lossy(&gst.stderr)
    );
    mark("git/passthrough");

    let syn = json_ok(&gdir, &["--json", "sync", "-m", "ultimate"], None);
    assert_eq!(syn["synced"], true);
    mark("sync");

    let backup2 = gdir.join("id.age");
    json_ok(
        &gdir,
        &[
            "--json",
            "identity",
            "export",
            "--out",
            backup2.to_str().unwrap(),
        ],
        None,
    );
    let g2 = unique_dir();
    git_in(
        Path::new("."),
        &[
            "clone",
            "-b",
            "main",
            remote.to_str().unwrap(),
            g2.join("store").to_str().unwrap(),
        ],
    );
    json_ok(
        &g2,
        &["--json", "identity", "import", backup2.to_str().unwrap()],
        None,
    );
    assert_eq!(
        json_ok(&g2, &["--json", "show", "g/s"], None)["value"],
        "synced"
    );
    mark("sync/clone-read");
}

fn cover_integrity_auth_path(dir: &Path) {
    let p1 = unique_dir();
    json_ok(&p1, &["--json", "init"], None);
    json_ok(&p1, &["--json", "insert", "p"], Some(b"old"));
    let ct = std::fs::read(store_age(&p1, "p")).unwrap();
    json_ok(&p1, &["--json", "insert", "p", "--force"], Some(b"new"));
    std::fs::write(store_age(&p1, "p"), ct).unwrap();
    let _ = json_err(&p1, &["--json", "show", "p"], None);
    mark("integrity/P1-stale");

    let _ = run(&p1, &["--json", "doctor", "--repair-generations"], None);
    assert_eq!(json_ok(&p1, &["--json", "show", "p"], None)["value"], "old");
    mark("integrity/P1-repair");

    json_ok(&p1, &["--json", "insert", "a"], Some(b"A"));
    json_ok(&p1, &["--json", "insert", "b"], Some(b"B"));
    let pa = store_age(&p1, "a");
    let pb = store_age(&p1, "b");
    let tmp = p1.join("t.age");
    std::fs::rename(&pa, &tmp).unwrap();
    std::fs::rename(&pb, &pa).unwrap();
    std::fs::rename(&tmp, &pb).unwrap();
    let _ = json_err(&p1, &["--json", "show", "a"], None);
    mark("integrity/P2-swap");

    json_ok(&p1, &["--json", "insert", "c"], Some(b"C"));
    std::fs::write(store_age(&p1, "c"), b"not-age-ciphertext").unwrap();
    let _ = json_err(&p1, &["--json", "show", "c"], None);
    mark("integrity/corrupt-ciphertext");

    let wrong = run_env(
        dir,
        &["--json", "show", "svc/token"],
        None,
        Some("wrong-pass"),
        &[],
    );
    assert!(!wrong.status.success());
    mark("auth/wrong-passphrase");

    let missing_pp = run_env(dir, &["--json", "show", "svc/token"], None, None, &[]);
    assert!(!missing_pp.status.success());
    mark("auth/missing-passphrase");

    for bad in ["../x", "a//b", "/abs", "CON", "", "a/./b"] {
        let bad_out = run(dir, &["--json", "insert", bad], Some(b"x"));
        assert!(!bad_out.status.success(), "path {bad} should fail");
    }
    mark("path/invalid");
}

fn cover_stress(dir: &Path) {
    for i in 0..STRESS_N {
        json_ok(
            dir,
            &["--json", "insert", &format!("stress/{i}"), "--force"],
            Some(format!("v{i}").as_bytes()),
        );
    }
    for i in 0..STRESS_N {
        assert_eq!(
            json_ok(dir, &["--json", "show", &format!("stress/{i}")], None)["value"],
            format!("v{i}")
        );
    }
    mark("stress/roundtrip");

    let nested = "n/a/b/c/d/e/f/g/h";
    json_ok(dir, &["--json", "insert", nested], Some(b"deep"));
    assert_eq!(
        json_ok(dir, &["--json", "show", nested], None)["value"],
        "deep"
    );
    mark("stress/nested");

    let large = vec![b'L'; LARGE_BYTES];
    json_ok(
        dir,
        &["--json", "insert", "stress/large", "--binary", "--force"],
        Some(&large),
    );
    let large_show = json_ok(dir, &["--json", "show", "stress/large"], None);
    assert_eq!(large_show["kind"], "binary");
    assert!(large_show["base64"].as_str().unwrap().len() > 100);
    mark("stress/large");

    // Unicode in secret values (path stays ASCII; policy is path-safe).
    json_ok(
        dir,
        &["--json", "insert", "stress/unicode", "--force"],
        Some("值=日本語\nnote: café\n".as_bytes()),
    );
    let uv = json_ok(dir, &["--json", "show", "stress/unicode"], None);
    assert!(uv["value"].as_str().unwrap().contains("日本語"));
    mark("stress/unicode");
}

fn assert_required_and_report() {
    let covered = COVERED.lock().unwrap().clone();
    eprintln!(
        "\n===== ULTIMATE CLI COVERAGE ({} marks) =====",
        covered.len()
    );
    for id in &covered {
        eprintln!("  [x] {id}");
    }
    let missing: Vec<_> = REQUIRED
        .iter()
        .copied()
        .filter(|r| !covered.contains(r))
        .collect();
    if !missing.is_empty() {
        eprintln!("----- MISSING REQUIRED -----");
        for m in &missing {
            eprintln!("  [ ] {m}");
        }
    }
    eprintln!("==========================================\n");
    for req in REQUIRED {
        assert!(
            covered.contains(req),
            "missing required coverage mark: {req}"
        );
    }
}

/// Single atomic umbrella: full matrix + hard-gated checklist.
#[test]
fn ultimate_command_matrix() {
    let dir = unique_dir();

    cover_global();
    cover_init(&dir);
    cover_aliases(&dir);
    cover_insert_show_ls(&dir);
    cover_gen_grep_otp(&dir);
    cover_cp_mv_rm(&dir);
    cover_run(&dir);
    cover_identity(&dir);
    cover_recipients(&dir);
    cover_doctor(&dir);
    cover_edit_passwd(&dir);
    cover_git_sync();
    cover_integrity_auth_path(&dir);
    cover_stress(&dir);

    assert_required_and_report();
}
