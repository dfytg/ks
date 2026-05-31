//! `ks identity` — show the public recipient, or back up / restore the identity.

use std::path::Path;
use std::process::ExitCode;

use ks::{Config, Error, Result, crypto};
use secrecy::SecretString;

use crate::cli::IdentityAction;
use crate::commands;
use crate::prompt;
use crate::terminal;

pub fn run(config: &Config, action: Option<IdentityAction>) -> Result<ExitCode> {
    match action {
        None => show_public(config),
        Some(IdentityAction::Export { out, armor }) => export(config, out.as_deref(), armor),
        Some(IdentityAction::Import { path, force }) => import(config, path.as_deref(), force),
    }
}

/// Prints this device's public recipient. Requires unlocking, since the public
/// key is derived from the secret key.
fn show_public(config: &Config) -> Result<ExitCode> {
    let identity = commands::unlock(config)?;
    let public = identity.to_public().to_string();
    if crate::output::is_json() {
        crate::output::emit(&serde_json::json!({ "public_key": public }));
    } else {
        println!("{public}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Backs up the (still passphrase-protected) identity to a file, or prints it as
/// ASCII armor to stdout when no destination is given.
fn export(config: &Config, out: Option<&Path>, armor: bool) -> Result<ExitCode> {
    let src = &config.identity_path;
    let json = crate::output::is_json();
    if let Some(dst) = out {
        crypto::export_identity(src, dst, armor)?;
        if json {
            crate::output::emit(&serde_json::json!({
                "exported": dst.display().to_string(),
                "armor": armor,
            }));
        } else {
            terminal::success(&format!("Identity backup written to {}", dst.display()));
            terminal::warn("Keep this backup offline and safe — it is the only copy of your key.");
        }
    } else {
        // No destination file: emit ASCII armor, which is safe on a terminal or
        // pipe regardless of the `armor` flag.
        let armored = crypto::armored_identity(src)?;
        if json {
            crate::output::emit(&serde_json::json!({ "identity": armored }));
        } else {
            println!("{armored}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Restores the identity from a backup file (or stdin), validating it with the
/// backup's passphrase before writing.
fn import(config: &Config, path: Option<&Path>, force: bool) -> Result<ExitCode> {
    let json = crate::output::is_json();
    let backup = match path {
        Some(p) => std::fs::read(p).map_err(Error::Io)?,
        None => prompt::stdin_bytes()?,
    };
    let passphrase = import_passphrase(json)?;
    let identity = crypto::import_identity(&backup, &config.identity_path, passphrase, force)?;
    let public = identity.to_public().to_string();
    if json {
        crate::output::emit(&serde_json::json!({
            "identity_path": config.identity_path.display().to_string(),
            "public_key": public,
        }));
    } else {
        terminal::success(&format!(
            "Identity restored to {}",
            config.identity_path.display()
        ));
        terminal::info(&format!("Public key (recipient): {public}"));
    }
    Ok(ExitCode::SUCCESS)
}

/// Resolves the passphrase that protects a backup: `KS_PASSPHRASE` if set,
/// otherwise an interactive prompt (refused in `--json` mode).
fn import_passphrase(json: bool) -> Result<SecretString> {
    if let Some(raw) = crate::hardening::take_env("KS_PASSPHRASE") {
        return Ok(SecretString::from(raw));
    }
    if json {
        return Err(Error::InvalidArgument(
            "KS_PASSPHRASE is required to import an identity in --json mode".to_owned(),
        ));
    }
    prompt::passphrase("Enter the backup's passphrase")
}
