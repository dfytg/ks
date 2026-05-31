//! `ks sync` — commit, pull (rebase) and push the store in one step.
//!
//! This removes the most common multi-device footgun: editing secrets and then
//! forgetting to commit before pushing. It also opens the store first, which
//! self-heals any recipient rotation a crash left mid-way, so a partially
//! rotated store is never pushed to a remote.

use std::process::ExitCode;

use ks::{Config, Error, Result, Store, git};

use crate::terminal;

pub fn run(config: &Config, message: &str) -> Result<ExitCode> {
    // Opening validates the store and self-heals any interrupted rotation.
    Store::open(config.clone())?;
    let root = &config.store_dir;
    if !git::is_repo(root) {
        return Err(Error::InvalidArgument(format!(
            "{} is not a git repository; run `ks init --git` or `ks git init`",
            root.display()
        )));
    }

    git::add_all(root)?;
    git::commit(root, message)?;
    git::pull_rebase(root)?;
    git::push(root)?;

    if crate::output::is_json() {
        crate::output::emit(&serde_json::json!({
            "synced": true,
            "store_dir": root.display().to_string(),
            "message": message,
        }));
    } else {
        terminal::success("Store synced (commit, pull --rebase, push)");
    }
    Ok(ExitCode::SUCCESS)
}
