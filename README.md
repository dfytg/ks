# ks

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![CI][ci-badge]][ci-url]
[![License][license-badge]][license-url]
[![Rust][rust-badge]][rust-url]

[crates-badge]: https://img.shields.io/crates/v/ks.svg
[crates-url]: https://crates.io/crates/ks
[docs-badge]: https://img.shields.io/docsrs/ks.svg
[docs-url]: https://docs.rs/ks
[ci-badge]: https://github.com/qntx/ks/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/qntx/ks/actions/workflows/ci.yml
[license-badge]: https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg
[license-url]: LICENSE-MIT
[rust-badge]: https://img.shields.io/badge/rust-edition%202024-orange.svg
[rust-url]: https://doc.rust-lang.org/edition-guide/
[`age`]: https://github.com/FiloSottile/age
[`rage`]: https://github.com/str4d/rage

> **Local-first, git-friendly secret manager built on [`age`].** One passphrase-protected identity, one encrypted file per secret, plain git for sync — zero PGP.

ks keeps API tokens, SSH/DB passphrases, TOTP seeds and CI secrets encrypted on disk and out of `.env` files. Encryption needs only public keys, so **storing a secret never asks for your passphrase** — and `ks run` injects them into a subprocess without ever touching disk.

## Highlights

- **Write without unlocking** — `insert`, `gen`, `rm` and `ls` need only public keys; only *reading* a secret unlocks the identity.
- **Modern crypto, zero PGP** — X25519 + ChaCha20-Poly1305 via `age`; identities and secrets interoperate with the [`age`] / [`rage`] CLIs.
- **Plain-text payloads** — first line is the value, `key: value` lines are fields; `age -d secret.age` stays human-readable, no bespoke container.
- **One file per secret** — clean `git diff`s, conflicts scoped to a single key, synced over plain git with no server.
- **Tamper-evident** — every secret is sealed in a path-bound envelope, so a relocated, swapped or rolled-back file is rejected on read.
- **Hardened by default** — secrets live in `Zeroizing` memory; the process disables core dumps, denies debuggers and (on Unix) locks pages out of swap; writes are atomic and lock-serialised.
- **Built to sync** — one-step `ks sync`, offline key backup/restore, and crash-consistent recipient rotation that self-heals after an interruption.
- **Agent-friendly** — a global `--json` flag turns every command non-interactive and machine-readable.
- **Batteries included** — built-in TOTP, subprocess injection, and an optional audit log.

## Install

**macOS / Linux**

```sh
curl -fsSL https://sh.qntx.fun/ks | sh
```

**Windows** (PowerShell)

```powershell
irm https://sh.qntx.fun/ks/ps | iex
```

Or with Cargo — `cargo install ks-cli`.

## Usage

```sh
# Bootstrap an identity + empty store (add --git to init a repo inside it)
ks init

# Store, read, search  (writing never asks for your passphrase)
ks insert github/token                        # masked prompt, or pipe via stdin
ks insert github/token --multiline            # first line = value, then `key: value` lines
ks insert tls/key.p12 --binary < key.p12      # store raw bytes verbatim
ks show github/token                          # print the whole secret
ks show github/token -f user                  # print a single field
ks show github/token -c                       # copy the value, auto-clear in 45 s
ks ls                                         # tree of all secrets
ks grep token --values                        # search paths (and decrypted contents)

# Generate, organise, rotate
ks gen aws/access-key -l 32 -c                # generate, store, copy
ks mv github/token github/pat                 # rename (re-encrypts to re-bind path)
ks cp github/pat backup/pat                   # copy   (re-encrypts to re-bind path)
ks rm backup/pat

# TOTP — store an otpauth:// URL, then read codes
printf 'otpauth://totp/GitHub:alice?secret=…' | ks insert github/totp
ks otp github/totp -c

# Inject secrets into a subprocess (never hits disk)
ks run --env github/pat=GITHUB_TOKEN -- npm test
ks run --prefix aws -- terraform apply        # AWS_ACCESS_KEY=…, AWS_SECRET_KEY=…

# Back up your key, then sync across devices with plain git
ks identity export --out ks-identity.age      # offline backup of your (encrypted) key
ks sync                                        # commit + pull --rebase + push, in one step
ks recipients add age1xyz…                    # authorise another device's public key

# Maintenance
ks doctor                                     # health-check
ks passwd                                     # rotate the identity passphrase
```

## Agent & JSON

The global `--json` flag makes any command emit one JSON object on stdout and run **fully non-interactively**: it never prompts, requires `KS_PASSPHRASE` to unlock, needs `--force` for destructive operations, and reports failures as `{"error": "…"}`.

```sh
export KS_PASSPHRASE='…'
echo -n 'ghp_xxx' | ks --json insert github/token   # {"path":"github/token","stored":true}
ks --json show github/token | jq -r .value          # ghp_xxx
```

The bundled skill [`skills/ks/SKILL.md`](skills/ks/SKILL.md) documents every command's JSON schema and the non-interactive contract.

> `show --json` prints the **plaintext** secret value — treat that output as sensitive.

## Library

```rust
use age::secrecy::SecretString;
use ks::{Config, Secret, Store, crypto};

let config = Config::load()?;

// Writing needs only the public recipients — no passphrase.
let store = Store::open(config.clone())?;
store.set("github/token", &Secret::new("ghp_xxx\nuser: alice"))?;

// Reading needs the unlocked identity.
let pp = SecretString::from(std::env::var("KS_PASSPHRASE")?);
let id = crypto::load_identity(&config.identity_path, pp)?;
println!("{}", store.get("github/token", &id)?.password());
```

## Storage & Configuration

```text
$XDG_DATA_HOME/ks/
├── identity.age          # passphrase-encrypted X25519 private key (local only)
├── logs/audit.jsonl      # optional metadata-only audit log (KS_AUDIT=1)
└── store/                # git root — safe to push
    ├── .age-recipients   # plaintext public-key allow-list
    ├── .ks.lock          # advisory write lock (git-ignored)
    └── github/
        └── token.age     # age envelope: path header + value + `key: value` fields
```

Secret paths are slash-separated; each segment allows ASCII letters, digits, `_`, `-` and `.` (so `aws/credentials.json` is stored intact) — never path traversal or reserved Windows names.

| Variable | Purpose |
| --- | --- |
| `KS_DIR` · `KS_STORE_DIR` · `KS_IDENTITY` | Override the store / identity paths |
| `KS_PASSPHRASE` | Non-interactive unlock (CI); read once, then scrubbed from the environment |
| `KS_CLIP_TIME` | Clipboard auto-clear delay in seconds (default `45`) |
| `KS_AUDIT` | `1` enables the append-only audit log |
| `NO_COLOR` | Disable colour (already off when output is piped) |

## Security

> **Not** independently audited — use at your own risk.

| Asset | Protected by |
| --- | --- |
| **Identity at rest** | `age` scrypt over a bech32 X25519 secret key |
| **Secrets at rest** | `age` X25519 recipient mode (ChaCha20-Poly1305 + HKDF) |
| **Integrity** | per-secret, path-bound envelope; relocation or rollback is rejected on read |
| **Memory** | `Zeroizing` on every secret-bearing type; cleared on drop |
| **Files** | `0o600` files / `0o700` dirs on Unix, created with `O_EXCL`; startup self-check warns on group/world access |
| **Process** | core dumps disabled, debugger attachment denied, pages locked out of swap (Unix); crash dumps suppressed (Windows) |
| **Concurrency** | store-wide advisory write lock; recipient rotation is crash-consistent — staged behind a commit marker and self-healed (rolled forward or back) on next open |
| **Unlocked key** | never written to disk or a keyring; lives only in process memory |

**Subprocess injection caveat:** `ks run` passes secrets through the child's **environment** — this keeps them off disk, but a process environment is not a sandbox. It is readable by other processes running as the same user (e.g. `/proc/<pid>/environ` on Linux) and is inherited by every descendant the child spawns. Prefer it to a committed `.env` file, but treat anything injected this way as visible to your own user session.

**Roadmap:** YubiKey / PIV (`age-plugin-yubikey`) and post-quantum recipients (`age-plugin-pq`) — the `identity.age` format is already plugin-ready.

## Backup & Multi-Device

`identity.age` is the **only** key that can decrypt your store, and it is *never* pushed to git — losing it loses everything. Back it up before you store anything important.

**Back up the key once, keep it offline:**

```sh
ks identity export --out ks-identity.age   # encrypted copy (still needs your passphrase)
ks identity export --armor                 # …or ASCII text to paste into a password manager
```

The backup stays passphrase-protected, so it is safe at rest in a password manager or on an offline drive — just not next to the git remote.

**Run a second device** (recommended — no single point of failure):

```sh
ks identity import ks-identity.age   # restore the same key on the new device
ks sync                              # commit + pull --rebase + push, in one step
```

Prefer one key per device? Authorise each instead of sharing:

```sh
ks recipients add <new-device-pubkey>   # re-encrypts every secret to the union, then `ks sync`
ks recipients rm  <lost-device-pubkey>  # revoke, then rotate any exposed secrets
```

`ks sync` stages, commits, rebases and pushes in one step, so you can never push without committing. The `.age-recipients` list uses git's `union` merge and recipient rotation is crash-consistent, so concurrent edits from two devices converge instead of corrupting the store.

> First push to a new remote sets the upstream once (`ks git push -u origin main`); use `ks sync` after that. Revoking a key cannot undo past reads — always rotate exposed secrets too.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this project shall be dual-licensed as above, without any additional terms or conditions.

---

<div align="center">

A **[QuantX](https://qntx.fun)** open-source project.

<a href="https://qntx.fun"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
