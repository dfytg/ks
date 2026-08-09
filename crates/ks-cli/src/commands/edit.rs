//! `ks edit` — edit a secret in `$EDITOR`.

use std::fs::OpenOptions;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command as Proc, ExitCode};
use std::time::{SystemTime, UNIX_EPOCH};

use ks::{Config, Error, Result, Secret};
use zeroize::Zeroizing;

use crate::commands;
use crate::terminal;

pub fn run(config: &Config, path: &str) -> Result<ExitCode> {
    if crate::output::is_json() {
        return Err(crate::output::interactive_only("edit"));
    }
    let store = commands::open_store(config)?;

    // Editing an existing secret needs the plaintext, so unlock; creating a new
    // one only writes, so stay locked (consistent with `insert`).
    let original = if store.exists(path) {
        let identity = commands::unlock(config)?;
        let secret = commands::get_secret(&store, path, &identity)?;
        if secret.is_binary() {
            return Err(Error::InvalidArgument(format!(
                "{path} is a binary secret and cannot be edited as text"
            )));
        }
        Zeroizing::new(secret.expose().to_owned())
    } else {
        Zeroizing::new(String::new())
    };

    let edited = edit_in_editor(&original)?;
    if *edited == *original {
        terminal::warn("No changes");
        return Ok(ExitCode::SUCCESS);
    }

    store.set(path, &Secret::new(edited.as_str()))?;
    terminal::success(&format!("Updated {path}"));
    Ok(ExitCode::SUCCESS)
}

/// Round-trips `initial` through `$EDITOR` via a short-lived owner-only temp
/// directory (`0700`) + file (`0600`), then zero-fills and removes both.
fn edit_in_editor(initial: &str) -> Result<Zeroizing<String>> {
    let dir = temp_dir_owner_only()?;
    let tmp = dir.join("secret.txt");
    let mut file = open_temp_owner_only(&tmp)?;
    file.write_all(initial.as_bytes())?;
    file.sync_all()?;
    // Drop the write handle so the editor can open the path.
    drop(file);

    let outcome = run_editor(&tmp);
    wipe_and_remove(&tmp, initial.len());
    drop(std::fs::remove_dir_all(&dir));
    outcome
}

fn run_editor(tmp: &Path) -> Result<Zeroizing<String>> {
    let (program, args) = editor();
    let status = Proc::new(&program)
        .args(&args)
        .arg(tmp)
        .status()
        .map_err(Error::Io)?;
    if !status.success() {
        return Err(Error::Io(std::io::Error::other(format!(
            "editor `{program}` exited without saving"
        ))));
    }
    Ok(Zeroizing::new(std::fs::read_to_string(tmp)?))
}

/// Resolves the editor invocation from `$EDITOR`/`$VISUAL` (falling back to a
/// platform default), split on whitespace into program plus arguments.
fn editor() -> (String, Vec<String>) {
    let raw = std::env::var("EDITOR")
        .or_else(|_| std::env::var("VISUAL"))
        .unwrap_or_else(|_| default_editor().to_owned());
    let mut parts = raw.split_whitespace().map(str::to_owned);
    let program = parts.next().unwrap_or_else(|| default_editor().to_owned());
    (program, parts.collect())
}

const fn default_editor() -> &'static str {
    if cfg!(windows) { "notepad" } else { "vi" }
}

/// Private directory under the process temp root (`0700` on Unix).
fn temp_dir_owner_only() -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ks-edit-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(Error::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = std::fs::metadata(&dir).map_err(Error::Io)?.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&dir, perms).map_err(Error::Io)?;
    }
    Ok(dir)
}

/// Creates a new exclusive temp file with owner-only mode on Unix.
fn open_temp_owner_only(path: &Path) -> Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path).map_err(Error::Io)
}

/// Best-effort zero-fill of the temp file then unlink. SSD residual data may
/// remain; this is defence-in-depth, not secure erase.
fn wipe_and_remove(path: &Path, approx_len: usize) {
    if let Ok(mut f) = OpenOptions::new().write(true).open(path) {
        let len = f
            .metadata()
            .ok()
            .and_then(|m| usize::try_from(m.len()).ok())
            .unwrap_or(approx_len);
        let zeros = vec![0u8; len.max(approx_len)];
        drop(f.seek(SeekFrom::Start(0)));
        drop(f.write_all(&zeros));
        drop(f.sync_all());
    }
    drop(std::fs::remove_file(path));
}
