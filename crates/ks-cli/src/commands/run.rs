//! `ks run -- <cmd>` — execute a command with secrets injected as env vars.

use std::process::{Command as Proc, ExitCode};

use ks::{Config, Error, Result, Secret};
use zeroize::Zeroizing;

use crate::commands;
use crate::terminal;

/// Env injection is text-only; binary secrets would silently become empty.
fn env_value(path: &str, secret: &Secret) -> Result<Zeroizing<String>> {
    if secret.is_binary() {
        return Err(Error::InvalidArgument(format!(
            "{path} is binary; cannot inject as an environment variable"
        )));
    }
    Ok(Zeroizing::new(secret.password().to_owned()))
}

pub fn run(config: &Config, env: &[String], prefix: &[String], cmd: &[String]) -> Result<ExitCode> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| Error::InvalidArgument("missing command after `--`".into()))?;

    let store = commands::open_store(config)?;
    let identity = commands::unlock(config)?;
    let mut injected: Vec<(String, Zeroizing<String>)> = Vec::new();

    for raw in env {
        let (path, name) = raw.split_once('=').ok_or_else(|| {
            Error::InvalidArgument(format!("expected `<path>=<NAME>`, got `{raw}`"))
        })?;
        let secret = commands::get_secret(&store, path, &identity)?;
        injected.push((name.to_owned(), env_value(path, &secret)?));
    }

    for pfx in prefix {
        let paths = store.list(pfx)?;
        if paths.is_empty() {
            terminal::warn(&format!("no secrets under `{pfx}`"));
        }
        for path in paths {
            let secret = commands::get_secret(&store, &path, &identity)?;
            // Keep the full logical path in the variable name (`aws/access_key`
            // -> `AWS_ACCESS_KEY`) so prefixes stay namespaced and two different
            // prefixes can never collide on the same suffix.
            let env_name = path.replace(['/', '-'], "_").to_uppercase();
            injected.push((env_name, env_value(&path, &secret)?));
        }
    }

    let mut child = Proc::new(program);
    child.args(args);
    for (name, value) in &injected {
        child.env(name, value.as_str());
    }

    let status = child.status().map_err(Error::Io)?;
    drop(injected);

    Ok(commands::child_exit_code(status))
}
