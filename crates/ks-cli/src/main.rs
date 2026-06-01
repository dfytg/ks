//! `ks` -- Key Store CLI entry point.

#![allow(
    unreachable_pub,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    reason = "binary crate: `pub` items are internal; a CLI legitimately writes to stdout/stderr and exits with structured non-zero codes"
)]

mod audit;
mod cli;
mod clipboard;
mod commands;
mod exit;
mod hardening;
mod output;
mod prompt;
mod terminal;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    hardening::harden();
    // Detached clipboard-clear helper: `ks __clipclear <secs>`, spawned by
    // `clipboard::copy_with_autoclear`. Handled before clap so it never appears
    // in the public command surface.
    if std::env::args().nth(1).as_deref() == Some(clipboard::CLEAR_ARG) {
        let secs = std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(45);
        clipboard::run_clear_daemon(secs);
        return ExitCode::SUCCESS;
    }
    let cli = cli::Cli::parse();
    output::init(cli.json);
    match commands::dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            output::error(&e);
            ExitCode::from(exit::for_error(&e).as_u8())
        }
    }
}
