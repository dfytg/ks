//! `ks doctor` — sanity-check the store, identity, recipients and git state.

use std::io::IsTerminal as _;
use std::path::Path;
use std::process::ExitCode;

use ks::{Config, Store, crypto, git, x25519};
use owo_colors::{OwoColorize as _, Stream, Style};

use crate::commands;
use crate::hardening;

/// Accumulates check results so they can be rendered as human lines (printed
/// inline as they run) or a single JSON object at the end.
#[derive(Default)]
struct Report {
    checks: Vec<CheckLine>,
    notes: Vec<String>,
    failures: usize,
}

struct CheckLine {
    label: String,
    ok: bool,
    detail: String,
}

impl Report {
    fn check(&mut self, label: &str, ok: bool, detail: &str) {
        if !ok {
            self.failures = self.failures.saturating_add(1);
        }
        if !crate::output::is_json() {
            let mark = if ok {
                "[OK]"
                    .if_supports_color(Stream::Stderr, |t| t.style(Style::new().green().bold()))
                    .to_string()
            } else {
                "[FAIL]"
                    .if_supports_color(Stream::Stderr, |t| t.style(Style::new().red().bold()))
                    .to_string()
            };
            eprintln!("  {mark} {label}: {detail}");
        }
        self.checks.push(CheckLine {
            label: label.to_owned(),
            ok,
            detail: detail.to_owned(),
        });
    }

    fn note(&mut self, detail: &str) {
        if !crate::output::is_json() {
            eprintln!(
                "  {} {detail}",
                "[*]".if_supports_color(Stream::Stderr, |t| t.cyan()),
            );
        }
        self.notes.push(detail.to_owned());
    }
}

pub fn run(config: &Config, repair_generations: bool) -> ExitCode {
    let mut report = Report::default();

    report_hardening(&mut report);

    report.check(
        "identity file present",
        config.identity_path.exists(),
        &config.identity_path.display().to_string(),
    );
    report.check(
        "store directory present",
        config.store_dir.exists(),
        &config.store_dir.display().to_string(),
    );

    let recipients_path = config.recipients_path();
    let recipients_ok =
        recipients_path.exists() && crypto::load_recipients(&recipients_path).is_ok();
    report.check(
        ".age-recipients valid",
        recipients_ok,
        &recipients_path.display().to_string(),
    );

    // Incomplete (no READY) journals are discarded on open; READY needs identity.
    if recipients_ok {
        match Store::open(config.clone()) {
            Ok(_) => note_pending_journals(config, &mut report),
            Err(e) => report.check("open store", false, &e.to_string()),
        }
    }
    check_permissions(config, &mut report);
    check_git_templates(config, &mut report);

    let identity = check_identity(config, &recipients_path, &mut report);
    if let Some(identity) = &identity {
        recover_ready_journals(config, identity, &mut report);
        // Repair before sample decrypt so --repair-generations can clear lag/stale
        // that would otherwise fail the secrets check in the same run.
        check_generations(config, identity, repair_generations, &mut report);
        check_secrets(config, identity, &mut report);
    }

    check_runtime_artifacts(config, &mut report);
    report_git(config, &mut report);

    finish(&report)
}

fn report_hardening(report: &mut Report) {
    let Some(status) = hardening::status() else {
        report.note("process hardening: status unavailable");
        return;
    };
    report.check(
        "hardening core_dump",
        status.core_dump.is_ok(),
        &status.core_dump.detail(),
    );
    // mlock is informational — failure is common in containers and never fatal.
    report.note(&format!(
        "hardening mlock ({}): {}",
        status.platform,
        status.mlock.detail()
    ));
    report.check(
        "hardening debugger_deny",
        status.debugger_deny.is_ok(),
        &status.debugger_deny.detail(),
    );
}

fn check_git_templates(config: &Config, report: &mut Report) {
    match git::ensure_git_templates(&config.store_dir) {
        Ok(delta) => {
            if delta.attributes_added.is_empty() && delta.ignore_added.is_empty() {
                report.check("git templates current", true, "ok");
            } else {
                let mut parts = Vec::new();
                if !delta.attributes_added.is_empty() {
                    parts.push(format!(
                        "appended attributes: {}",
                        delta.attributes_added.join(", ")
                    ));
                }
                if !delta.ignore_added.is_empty() {
                    parts.push(format!(
                        "appended ignore: {}",
                        delta.ignore_added.join(", ")
                    ));
                }
                report.note(&parts.join("; "));
            }
        }
        Err(e) => report.check("git templates", false, &e.to_string()),
    }
}

fn check_generations(
    config: &Config,
    identity: &x25519::Identity,
    repair: bool,
    report: &mut Report,
) {
    let store = match commands::open_store(config) {
        Ok(s) => s,
        Err(e) => {
            report.check("open store for generations", false, &e.to_string());
            return;
        }
    };
    if repair {
        match store.repair_generations(identity) {
            Ok(report_repair) => {
                report.note(&format!(
                    "repaired .ks-generations ({} entries)",
                    report_repair.entries
                ));
                if !report_repair.skipped.is_empty() {
                    report.note(&format!(
                        "skipped unreadable: {} — `ks rm <path>` then re-insert from known plaintext (not mv/cp/rotate)",
                        report_repair.skipped.join(", ")
                    ));
                }
            }
            Err(e) => {
                report.check("repair-generations", false, &e.to_string());
                return;
            }
        }
    }
    match store.generation_census(identity) {
        Ok(c) => {
            report.check(
                "generations fully protected",
                c.fully_protected,
                &format!(
                    "sealed={} lag={} stale={} missing_index={} tombstones={}",
                    c.sealed_count,
                    c.lag_paths.len(),
                    c.stale_paths.len(),
                    c.missing_index.len(),
                    c.tombstone_count
                ),
            );
            if !c.lag_paths.is_empty() {
                report.note(&format!(
                    "generation lag on: {} (run doctor --repair-generations)",
                    c.lag_paths.join(", ")
                ));
            }
            if !c.stale_paths.is_empty() {
                report.note(&format!(
                    "stale (envelope < index) on: {} — single-device: doctor --repair-generations; multi-device durable: set known plaintext while index is still high (do not repair first)",
                    c.stale_paths.join(", ")
                ));
            }
        }
        Err(e) => report.check("generations census", false, &e.to_string()),
    }
}

fn note_pending_journals(config: &Config, report: &mut Report) {
    let rotate = config.store_dir.join(".ks-rotate");
    if rotate.join("READY").exists() {
        report.note(
            "interrupted recipient rotation (READY) pending unlock — doctor will recover when identity unlocks",
        );
    }
    let mv = config.store_dir.join(".ks-move");
    if mv.join("READY").exists() {
        report.note(
            "interrupted rename (READY) pending unlock — doctor will recover when identity unlocks",
        );
    }
}

fn recover_ready_journals(config: &Config, identity: &x25519::Identity, report: &mut Report) {
    let store = match Store::open(config.clone()) {
        Ok(s) => s,
        Err(e) => {
            report.check("open store for journal recover", false, &e.to_string());
            return;
        }
    };
    if config.store_dir.join(".ks-rotate").join("READY").exists() {
        match store.recover_rotation(identity) {
            Ok(ks::RotationRecovery::Completed) => {
                report.note("recovered interrupted recipient rotation (authenticated READY)");
            }
            Ok(_) => {}
            Err(e) => report.check("recover interrupted rotation", false, &e.to_string()),
        }
    }
    if config.store_dir.join(".ks-move").join("READY").exists() {
        match store.recover_move(identity) {
            Ok(ks::MoveRecovery::Completed) => {
                report.note("recovered interrupted rename (authenticated READY)");
            }
            Ok(_) => {}
            Err(e) => report.check("recover interrupted rename", false, &e.to_string()),
        }
    }
}

fn finish(report: &Report) -> ExitCode {
    let ok = report.failures == 0;
    if crate::output::is_json() {
        let checks: Vec<serde_json::Value> = report
            .checks
            .iter()
            .map(|line| {
                serde_json::json!({ "check": line.label, "ok": line.ok, "detail": line.detail })
            })
            .collect();
        crate::output::emit(&serde_json::json!({
            "checks": checks,
            "notes": report.notes,
            "failures": report.failures,
            "ok": ok,
        }));
    } else if ok {
        eprintln!(
            "\n{} all checks passed",
            "[OK]".if_supports_color(Stream::Stderr, |t| t.style(Style::new().green().bold())),
        );
    } else {
        eprintln!(
            "\n{} {} check(s) failed",
            "[FAIL]".if_supports_color(Stream::Stderr, |t| t.style(Style::new().red().bold())),
            report
                .failures
                .to_string()
                .if_supports_color(Stream::Stderr, |t| t.bold()),
        );
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn report_git(config: &Config, report: &mut Report) {
    if !git::is_repo(&config.store_dir) {
        report.note("git: not a repository");
        return;
    }
    match git::status(&config.store_dir) {
        Ok(out) => {
            if crate::output::is_json() {
                let branch = out.lines().next().unwrap_or("").trim().to_owned();
                report.notes.push(format!("git {branch}"));
            } else {
                eprintln!(
                    "  {} git status:",
                    "[*]".if_supports_color(Stream::Stderr, |t| t.cyan()),
                );
                for line in out.lines() {
                    eprintln!("    {line}");
                }
            }
        }
        Err(e) => report.check("git status", false, &e.to_string()),
    }
}

fn check_identity(
    config: &Config,
    recipients_path: &Path,
    report: &mut Report,
) -> Option<x25519::Identity> {
    let can_unlock = std::env::var("KS_PASSPHRASE").is_ok_and(|v| !v.is_empty())
        || std::io::stdin().is_terminal();
    if !can_unlock {
        report.note("identity unlocks: skipped (set KS_PASSPHRASE for non-interactive checks)");
        return None;
    }
    let identity = match commands::unlock(config) {
        Ok(id) => id,
        Err(e) => {
            report.check("identity unlocks", false, &e.to_string());
            return None;
        }
    };
    report.check("identity unlocks", true, "ok (env or prompt)");
    if let Ok(list) = crypto::load_recipients(recipients_path) {
        let own = identity.to_public();
        report.check(
            "identity is in .age-recipients",
            crypto::recipients_contain(&list, &own),
            &own.to_string(),
        );
    }
    Some(identity)
}

fn check_permissions(config: &Config, report: &mut Report) {
    let issues = config.permission_issues();
    if !issues.is_empty() {
        for issue in &issues {
            report.check("file permissions", false, issue);
        }
    } else if cfg!(unix) {
        report.check("file permissions owner-only", true, "ok");
    } else {
        report.note("file permissions: not enforced on this platform (Windows ACLs out of scope)");
    }
}

fn check_secrets(config: &Config, identity: &x25519::Identity, report: &mut Report) {
    const SAMPLE: usize = 20;
    let store = match commands::open_store(config) {
        Ok(s) => s,
        Err(e) => {
            report.check("open store for secret sample", false, &e.to_string());
            return;
        }
    };
    let paths = match store.list("") {
        Ok(p) => p,
        Err(e) => {
            report.check("list secrets for sample", false, &e.to_string());
            return;
        }
    };
    if paths.is_empty() {
        return;
    }
    let checked = paths.len().min(SAMPLE);
    let bad = paths
        .iter()
        .take(SAMPLE)
        .filter(|path| commands::get_secret(&store, path, identity).is_err())
        .count();
    report.check(
        &format!("secrets decrypt & verify ({checked} sampled)"),
        bad == 0,
        &if bad == 0 {
            "ok".to_owned()
        } else {
            format!("{bad} failed integrity/decrypt")
        },
    );
}

fn check_runtime_artifacts(config: &Config, report: &mut Report) {
    let temps = orphan_temp_count(&config.store_dir);
    if temps > 0 {
        report.note(&format!(
            "{temps} leftover *.tmp scratch file(s) under the store — safe to delete"
        ));
    }
}

fn orphan_temp_count(root: &Path) -> usize {
    let mut count = 0;
    count_temps(root, &mut count);
    count
}

fn count_temps(dir: &Path, count: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_dir = path.is_dir();
        let is_hidden = entry.file_name().to_string_lossy().starts_with('.');
        if is_dir && !is_hidden {
            count_temps(&path, count);
        } else if !is_dir && path.extension().and_then(|e| e.to_str()) == Some("tmp") {
            *count = count.saturating_add(1);
        }
    }
}
