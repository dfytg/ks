# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] — 2026-08-09

### Breaking

- **Envelope:** only `ksenv/2` is accepted on read. Legacy `ksenv/1` is rejected (`Error::Tampered`). There is **no** last-chance dual-read in 0.7.
- **Removed** `KS_ALLOW_STALE` and `Store::get_allowing_stale`. P1 (older envelope under newer index) is always enforced on `get`.
- **`Store::repair_generations`** now returns `RepairReport { entries, skipped }` instead of `usize`. Unreadable paths are skipped (prior index floors preserved).
- **`GenerationCensus`:** `v1_count` / `v2_count` replaced by `sealed_count`.
- **`Store::open`** no longer mutates `.gitattributes` / `.gitignore`. Templates are ensured on create, `git::init`, and `ks doctor`.

### Added

- Path-bound **generation** envelope (`ksenv/2`) and git-synced **`.ks-generations`** index (`merge=union`, max-reduce, delete tombstones).
- Crash-consistent **rename** via `.ks-move/` READY protocol (mirrors recipient rotation).
- **Authenticated READY recovery:** incomplete journals (no `READY`) are discarded on `open`; committed `READY` journals apply only via identity-checked `recover_rotation` / `recover_move` (or the next authenticated write / doctor unlock) — planted staging cannot rewrite recipients on bare open.
- Process **hardening status** (`HardenStatus`), doctor reporting, optional `KS_STRICT_HARDEN`.
- `ks doctor --repair-generations` with skip reporting for unreadable secrets.
- Safer **edit** temp lifecycle (private `0700` dir, `create_new` + `0600` file, zero-fill before unlink).
- Honest Security documentation: P1 partial temporal integrity, permanent non-property **N1** (co-rolled secret+index / full commit restore not detected).

### Changed

- `cargo-deny` config simplified (kobe-style); workspace version **0.7.0**.
- CLI help for `mv` / `cp` matches library behaviour (re-encrypt + unlock).

### Security / recovery notes

| Situation | Action |
| --- | --- |
| Index lag (envelope gen &gt; index) | `ks doctor --repair-generations` |
| Stale, single device (keep ciphertext) | `ks doctor --repair-generations` then `get` |
| Stale, multi-device, known plaintext | `ks set` / `insert` **while the high index is still present** (`H+1`). **Do not repair first** |
| Unreadable / leftover v1 ciphertext | `ks rm <path>` then re-insert from known plaintext — **not** `mv` / `cp` / rotate |

#### Upgrading from 0.6.x

1. On **0.6**, run `ks doctor` until no `ksenv/1` secrets remain (rewrite with `set` / `mv` / `cp` / rotate while dual-read still works).
2. Repair lag/missing index with `ks doctor --repair-generations` on 0.6 if available.
3. Install **0.7**. Secrets still on v1 become unreadable without an external plaintext backup.

### Fixed

- Documentation overclaiming generic “rollback rejection” (path binding and P1 are now stated precisely).

## [0.6.0] — unreleased intermediate

Development train that introduced generations and READY rename; superseded by 0.7.0 breaking cleanup. Operators should treat **0.7.0** as the first public line for this architecture.
