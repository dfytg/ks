//! `ks init` — bootstrap a new identity and store.

use std::io::IsTerminal as _;
use std::process::ExitCode;

use cliclack::{intro, outro};
use ks::{Config, Error, Result, Store, crypto, git as git_};
use secrecy::SecretString;

use crate::prompt;
use crate::terminal;

pub fn run(config: &Config, init_git: bool) -> Result<ExitCode> {
    let json = crate::output::is_json();

    // Already initialised: never re-create or overwrite the identity/recipients.
    // With `--git` we idempotently add the git layer to the existing store;
    // without it this is a plain "already exists" error so a stray `ks init`
    // can never clobber existing key material.
    if config.identity_path.exists() {
        return enable_git_on_existing(config, init_git, json);
    }

    let interactive = std::io::stdin().is_terminal() && !json;

    let pp = if let Some(raw) = crate::hardening::take_env("KS_PASSPHRASE") {
        SecretString::from(raw)
    } else if json {
        return Err(Error::InvalidArgument(
            "KS_PASSPHRASE is required to set the master passphrase in --json mode".to_owned(),
        ));
    } else {
        intro("ks: initialise key store")?;
        prompt::new_passphrase("Choose a master passphrase")?
    };
    let id = crypto::create_identity(&config.identity_path, pp)?;
    let store = Store::create(config.clone(), &id, &[])?;
    if init_git {
        git_::init(store.root())?;
    }

    if json {
        crate::output::emit(&serde_json::json!({
            "identity_path": config.identity_path.display().to_string(),
            "store_dir": store.root().display().to_string(),
            "public_key": id.to_public().to_string(),
            "git": init_git,
        }));
        return Ok(ExitCode::SUCCESS);
    }

    terminal::success(&format!(
        "Identity written to {}",
        config.identity_path.display()
    ));
    terminal::success(&format!("Store created at {}", store.root().display()));
    terminal::info(&format!("Public key (recipient): {}", id.to_public()));
    if init_git {
        terminal::success("Initialised git repository in store");
    }
    if interactive {
        outro("Use `ks insert <path>` to store your first secret.")?;
    }
    Ok(ExitCode::SUCCESS)
}

/// Handles `ks init` on a store that already has an identity: optionally add the
/// git layer, but never touch existing key material. `git::init` is idempotent,
/// so re-running is safe.
fn enable_git_on_existing(config: &Config, init_git: bool, json: bool) -> Result<ExitCode> {
    if !init_git {
        return Err(Error::IdentityExists(config.identity_path.clone()));
    }
    let store_dir = &config.store_dir;
    if !store_dir.exists() {
        return Err(Error::StoreNotFound(store_dir.clone()));
    }
    let was_repo = git_::is_repo(store_dir);
    if !was_repo {
        git_::init(store_dir)?;
    }

    if json {
        crate::output::emit(&serde_json::json!({
            "store_dir": store_dir.display().to_string(),
            "git": true,
            "already_initialised": true,
            "git_added": !was_repo,
        }));
        return Ok(ExitCode::SUCCESS);
    }

    if was_repo {
        terminal::info(&format!(
            "Store at {} is already a git repository",
            store_dir.display()
        ));
    } else {
        terminal::success(&format!(
            "Initialised git repository in existing store at {}",
            store_dir.display()
        ));
        terminal::info("Connect a remote with `ks git remote add origin <url>`, then `ks sync`");
    }
    Ok(ExitCode::SUCCESS)
}
