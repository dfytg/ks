//! Thin wrapper over the system `git` binary.
//!
//! We deliberately shell out instead of pulling in a Rust git library
//! (`gix` etc.): users already have SSH agents, signing keys, credential
//! helpers and ssh config configured for the `git` they use elsewhere, and
//! it is futile to reimplement that surface.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::error::{Error, Result};

const BIN: &str = "git";

/// Lines required in `.gitattributes` for a modern ks store.
const REQUIRED_ATTRIBUTES: &[&str] = &[
    "*.age binary -diff -merge",
    ".age-recipients text eol=lf merge=union",
    ".ks-generations text eol=lf merge=union",
];

/// Lines required in `.gitignore` for a modern ks store.
const REQUIRED_IGNORE: &[&str] = &[".ks.lock", ".ks-rotate/", ".ks-move/", "*.tmp"];

/// What [`ensure_git_templates`] added or found missing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TemplateDelta {
    /// Attribute lines that were appended.
    pub attributes_added: Vec<String>,
    /// Ignore lines that were appended.
    pub ignore_added: Vec<String>,
}

/// Returns `true` if `dir` contains a `.git` directory or file.
#[must_use]
pub fn is_repo(dir: &Path) -> bool {
    dir.join(".git").exists()
}

/// Initialises a git repository at `dir` with a sensible `.gitattributes` and
/// `.gitignore`.
///
/// # Errors
/// Returns [`Error::Command`] if `git init` fails or [`Error::Io`] on write.
pub fn init(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    run(dir, &["init", "--initial-branch=main"])?;
    ensure_git_templates(dir)?;
    Ok(())
}

/// Ensures store git templates contain all required modern lines.
///
/// Appends **missing** lines only; never rewrites user comments or existing
/// order. Creates the file with the full modern template when absent.
/// Call from [`crate::store::Store::create`], [`init`], or `ks doctor` — not
/// from [`crate::store::Store::open`] (open must not mutate policy files).
///
/// # Errors
/// [`Error::Io`] on filesystem failure.
pub fn ensure_git_templates(dir: &Path) -> Result<TemplateDelta> {
    Ok(TemplateDelta {
        attributes_added: ensure_lines(&dir.join(".gitattributes"), REQUIRED_ATTRIBUTES)?,
        ignore_added: ensure_lines(&dir.join(".gitignore"), REQUIRED_IGNORE)?,
    })
}

/// Ensures each of `required` appears as a full line in `path` (create or append).
fn ensure_lines(path: &Path, required: &[&str]) -> Result<Vec<String>> {
    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    let present: std::collections::HashSet<&str> = existing
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    let mut added = Vec::new();
    let mut append = String::new();
    for line in required {
        if !present.contains(line) {
            append.push_str(line);
            append.push('\n');
            added.push((*line).to_owned());
        }
    }
    if added.is_empty() {
        return Ok(added);
    }

    if existing.is_empty() {
        std::fs::write(path, append)?;
    } else {
        let mut body = existing;
        if !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&append);
        std::fs::write(path, body)?;
    }
    Ok(added)
}

/// `git add -A`.
///
/// # Errors
/// Returns [`Error::Command`] on failure.
pub fn add_all(dir: &Path) -> Result<()> {
    run(dir, &["add", "-A"])?;
    Ok(())
}

/// `git commit -m <message>`. Returns `Ok(())` if there was nothing to commit.
///
/// # Errors
/// Returns [`Error::Command`] only for actual failures, not for the
/// "nothing to commit" case.
pub fn commit(dir: &Path, message: &str) -> Result<()> {
    let output = command(dir, &["commit", "-m", message])
        .output()
        .map_err(Error::Io)?;
    if output.status.success() {
        return Ok(());
    }
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if combined.contains("nothing to commit") || combined.contains("no changes added") {
        return Ok(());
    }
    Err(Error::Command {
        cmd: format!("git commit -m {message:?}"),
        status: output.status.code().unwrap_or(-1),
        stderr: combined,
    })
}

/// `git pull --rebase --autostash`.
///
/// # Errors
/// Returns [`Error::Command`] on failure.
pub fn pull_rebase(dir: &Path) -> Result<()> {
    run(dir, &["pull", "--rebase", "--autostash"])?;
    Ok(())
}

/// `git push`.
///
/// # Errors
/// Returns [`Error::Command`] on failure.
pub fn push(dir: &Path) -> Result<()> {
    run(dir, &["push"])?;
    Ok(())
}

/// `git status -sb`.
///
/// # Errors
/// Returns [`Error::Command`] on failure.
pub fn status(dir: &Path) -> Result<String> {
    run(dir, &["status", "-sb"])
}

/// `git log -n <n> --oneline`.
///
/// # Errors
/// Returns [`Error::Command`] on failure.
pub fn log(dir: &Path, n: usize) -> Result<String> {
    let limit = format!("-n{n}");
    run(dir, &["log", "--oneline", &limit])
}

fn run(dir: &Path, args: &[&str]) -> Result<String> {
    let output = command(dir, args).output().map_err(Error::Io)?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(Error::Command {
            cmd: format!("git {}", args.join(" ")),
            status: output.status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

fn command(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_templates_appends_missing_lines() {
        let root = std::env::temp_dir().join(format!("ks-git-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).expect("dir");
        std::fs::write(
            root.join(".gitattributes"),
            "*.age binary -diff -merge\n.age-recipients text eol=lf merge=union\n",
        )
        .expect("attr");
        std::fs::write(root.join(".gitignore"), ".ks.lock\n.ks-rotate/\n*.tmp\n").expect("ign");

        let delta = ensure_git_templates(&root).expect("ensure");
        assert!(
            delta
                .attributes_added
                .iter()
                .any(|l| l.contains(".ks-generations"))
        );
        assert!(delta.ignore_added.iter().any(|l| l.contains(".ks-move")));

        let again = ensure_git_templates(&root).expect("idempotent");
        assert!(again.attributes_added.is_empty());
        assert!(again.ignore_added.is_empty());
        drop(std::fs::remove_dir_all(&root));
    }
}
