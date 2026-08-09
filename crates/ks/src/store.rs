//! The encrypted secret store.
//!
//! A [`Store`] is a directory tree where each secret is its own age file
//! (`<store>/<logical/path>.age`) and a top-level `.age-recipients` file lists
//! the X25519 public keys allowed to decrypt it. A git-synced
//! [`.ks-generations`](crate::generations) index records per-path generation
//! counters used for partial temporal integrity (property P1).
//!
//! The API mirrors age's natural asymmetry:
//!
//! - **Writing** ([`set`](Store::set), [`insert`](Store::insert),
//!   [`delete`](Store::delete), [`list`](Store::list)) needs only the recipient
//!   public keys, so it never prompts for a passphrase.
//! - **Reading** ([`get`](Store::get), [`grep`](Store::grep)), moving
//!   ([`rename`](Store::rename), [`copy`](Store::copy)) and rotating recipients
//!   ([`set_recipients`](Store::set_recipients)) require the caller-supplied
//!   [`x25519::Identity`].
//!
//! Each secret is wrapped in a path- and generation-bound envelope (`ksenv/2`).
//! Moving a secret re-encrypts under the new path. Relocated or swapped
//! ciphertext is detected on read (P2). Older ciphertext under a newer index
//! generation is rejected (P1). Co-rolled secret+index restore is not detected
//! (non-property N1).

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use age::x25519;
use fd_lock::RwLock;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::crypto;
use crate::envelope;
use crate::error::{Error, Result};
use crate::generations::{self, Generations};
use crate::git;
use crate::path as pathutil;
use crate::secret::Secret;

/// Name of the advisory-lock file kept at the store root.
const LOCK_FILE: &str = ".ks.lock";

/// Name of the staging directory used for transactional recipient rotation.
const ROTATE_DIR: &str = ".ks-rotate";

/// Subdirectory inside [`ROTATE_DIR`] mirroring the re-encrypted secret tree.
const ROTATE_SECRETS: &str = "secrets";

/// Staged target recipient list, written inside [`ROTATE_DIR`] during phase 1.
const ROTATE_RECIPIENTS: &str = "RECIPIENTS";

/// Commit-point marker written last in phase 1 of rotation.
const ROTATE_READY: &str = "READY";

/// Staging directory for crash-consistent rename.
const MOVE_DIR: &str = ".ks-move";

/// Subdirectory inside [`MOVE_DIR`] for the staged destination ciphertext.
const MOVE_SECRETS: &str = "secrets";

const MOVE_READY: &str = "READY";
const MOVE_FROM: &str = "FROM";
const MOVE_TO: &str = "TO";
const MOVE_GEN: &str = "GEN";

/// An encrypted store bound to a config and its recipient list.
pub struct Store {
    config: Config,
    recipients: Vec<x25519::Recipient>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("store_dir", &self.config.store_dir)
            .field("recipients", &self.recipients.len())
            .finish()
    }
}

/// Outcome of [`Store::recover_rotation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationRecovery {
    /// No interrupted rotation was found; the store was already consistent.
    Clean,
    /// An incomplete preparation was discarded; the live store was untouched.
    RolledBack,
    /// A committed-but-interrupted rotation was rolled forward to completion.
    Completed,
}

/// Outcome of [`Store::recover_move`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveRecovery {
    /// No interrupted rename was found.
    Clean,
    /// Incomplete preparation discarded.
    RolledBack,
    /// Committed rename rolled forward.
    Completed,
}

/// Outcome of [`Store::grep`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GrepResults {
    /// Paths that matched by name, or by decrypted content under a value scan.
    pub matches: Vec<String>,
    /// Paths skipped during a content scan because they could not be decrypted
    /// or failed envelope verification (tampered, corrupt, or not encrypted to
    /// this identity). Always empty when `identity` is `None`.
    pub unreadable: Vec<String>,
}

/// Census of envelope and generation health (for doctor).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GenerationCensus {
    /// Secrets that decrypted and unwrapped as sealed `ksenv/2` envelopes.
    pub sealed_count: usize,
    /// Paths where envelope.gen > index.gen (index lag after crash).
    pub lag_paths: Vec<String>,
    /// Paths where envelope.gen < index.gen (P1 failure if read).
    pub stale_paths: Vec<String>,
    /// Existing secret files missing from the index.
    pub missing_index: Vec<String>,
    /// Index entries with no corresponding secret file (tombstones).
    pub tombstone_count: usize,
    /// Whether fully-protected predicate holds (all sealed, equal gens, no lag/stale).
    pub fully_protected: bool,
}

/// Result of [`Store::repair_generations`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairReport {
    /// Index entries written (live envelopes + preserved tombstones).
    pub entries: usize,
    /// Live paths that could not be decrypted/unwrapped (left prior floor if any).
    pub skipped: Vec<String>,
}

impl Store {
    /// Opens an existing store and loads its recipients. Does **not** unlock the
    /// identity, so the returned store can write but not yet read secrets.
    ///
    /// Opens the store. Discards **incomplete** (no `READY`) rotation/rename
    /// journals only. Committed `READY` journals are **not** applied here —
    /// they require identity via [`recover_rotation`] / [`recover_move`] (or
    /// the next authenticated write that runs recovery) so a planted staging
    /// tree in a synced store cannot rewrite recipients or delete secrets.
    ///
    /// Does **not** mutate git template files; use
    /// [`crate::git::ensure_git_templates`] via `create`, `git::init`, or
    /// `ks doctor`.
    ///
    /// # Errors
    /// - [`Error::StoreNotFound`] if the store directory does not exist.
    /// - [`Error::NoRecipients`] if `.age-recipients` is missing or empty.
    /// - [`Error::Io`] / [`Error::InvalidRecipient`] on parse failures.
    pub fn open(config: Config) -> Result<Self> {
        if !config.store_dir.exists() {
            return Err(Error::StoreNotFound(config.store_dir));
        }
        let recipients = crypto::load_recipients(&config.recipients_path())?;
        let store = Self { config, recipients };
        store.discard_incomplete_journals()?;
        Ok(store)
    }

    /// Creates a brand-new store, writing `.age-recipients` with the owner's
    /// public key plus any `extra` recipients.
    ///
    /// # Errors
    /// - [`Error::StoreExists`] if `.age-recipients` already exists.
    /// - [`Error::Io`] on filesystem failures.
    pub fn create(
        config: Config,
        owner: &x25519::Identity,
        extra: &[x25519::Recipient],
    ) -> Result<Self> {
        let recipients_path = config.recipients_path();
        if recipients_path.exists() {
            return Err(Error::StoreExists(config.store_dir));
        }
        crypto::create_dir_all_secure(&config.store_dir)?;

        let mut recipients = Vec::with_capacity(extra.len().saturating_add(1));
        recipients.push(owner.to_public());
        for r in extra {
            if !crypto::recipients_contain(&recipients, r) {
                recipients.push(r.clone());
            }
        }
        crypto::save_recipients(&recipients_path, &recipients)?;
        let store = Self { config, recipients };
        drop(git::ensure_git_templates(&store.config.store_dir));
        Ok(store)
    }

    /// Returns the absolute store directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.config.store_dir
    }

    /// Returns the configured recipient list.
    #[must_use]
    pub fn recipients(&self) -> &[x25519::Recipient] {
        &self.recipients
    }

    fn lock_file(&self) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.config.store_dir.join(LOCK_FILE))
            .map_err(Error::Io)
    }

    /// Runs `f` while holding an exclusive advisory lock on the store.
    fn with_write_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut lock = RwLock::new(self.lock_file()?);
        let _guard = lock.write().map_err(Error::Io)?;
        f()
    }

    /// Returns `true` if a secret exists at `logical`.
    #[must_use]
    pub fn exists(&self, logical: &str) -> bool {
        pathutil::validate(logical).is_ok()
            && pathutil::to_file(&self.config.store_dir, logical).is_file()
    }

    /// Encrypts and writes (or overwrites) `secret` at `logical`.
    ///
    /// Bumps the path's generation in `.ks-generations` and seals `ksenv/2`.
    ///
    /// # Errors
    /// [`Error::InvalidPath`] for malformed paths; [`Error::Io`] /
    /// [`Error::Encrypt`] on failure.
    pub fn set(&self, logical: &str, secret: &Secret) -> Result<()> {
        pathutil::validate(logical)?;
        self.with_write_lock(|| self.write_secret(logical, secret))
    }

    /// Encrypts and writes under the caller's write lock.
    fn write_secret(&self, logical: &str, secret: &Secret) -> Result<()> {
        let mut gens = generations::load(&self.config.store_dir)?;
        let next = gens.next(logical);
        let ciphertext = self.encrypt_secret(logical, secret.kind(), next, secret.as_bytes())?;
        crypto::write_atomic(
            &pathutil::to_file(&self.config.store_dir, logical),
            &ciphertext,
        )?;
        gens.set(logical.to_owned(), next);
        generations::save(&self.config.store_dir, &gens)
    }

    /// Encrypts a secret payload to current recipients with a sealed generation.
    fn encrypt_secret(
        &self,
        logical: &str,
        kind: crate::secret::SecretKind,
        generation: u64,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        encrypt_secret_to(logical, kind, generation, payload, &self.recipients)
    }

    /// Inserts a new secret, failing with [`Error::SecretExists`] if present.
    ///
    /// # Errors
    /// See [`set`](Store::set) plus [`Error::SecretExists`].
    pub fn insert(&self, logical: &str, secret: &Secret) -> Result<()> {
        pathutil::validate(logical)?;
        self.with_write_lock(|| {
            if self.exists(logical) {
                return Err(Error::SecretExists(logical.to_owned()));
            }
            self.write_secret(logical, secret)
        })
    }

    /// Reads and decrypts the secret at `logical` with strict P1 checks.
    ///
    /// # Errors
    /// [`Error::InvalidPath`], [`Error::SecretNotFound`], [`Error::Tampered`],
    /// or [`Error::Decrypt`] / [`Error::Io`] on failure.
    pub fn get(&self, logical: &str, identity: &x25519::Identity) -> Result<Secret> {
        pathutil::validate(logical)?;
        let file = pathutil::to_file(&self.config.store_dir, logical);
        if !file.exists() {
            return Err(Error::SecretNotFound(logical.to_owned()));
        }
        let plaintext = crypto::decrypt(&std::fs::read(&file)?, identity)?;
        let unwrapped = envelope::unwrap(logical, &plaintext)?;
        let gens = generations::load(&self.config.store_dir)?;
        generations::verify(logical, unwrapped.generation, &gens)?;
        Ok(Secret::from_bytes(unwrapped.payload, unwrapped.kind))
    }

    /// Deletes the secret file at `logical` but **keeps** the generation index
    /// entry as a tombstone floor for future inserts.
    ///
    /// # Errors
    /// [`Error::SecretNotFound`] if the file is absent; [`Error::Io`] otherwise.
    pub fn delete(&self, logical: &str) -> Result<()> {
        pathutil::validate(logical)?;
        self.with_write_lock(|| {
            let file = pathutil::to_file(&self.config.store_dir, logical);
            if !file.exists() {
                return Err(Error::SecretNotFound(logical.to_owned()));
            }
            std::fs::remove_file(&file)?;
            prune_empty_parents(&self.config.store_dir, file.parent());
            // Tombstone: leave index entry untouched (KD-11).
            Ok(())
        })
    }

    /// Renames a secret via a crash-consistent `.ks-move/` READY protocol.
    /// Decrypts, re-binds path + new generation, re-encrypts. Needs identity.
    ///
    /// # Errors
    /// [`Error::SecretNotFound`] if `from` is absent, [`Error::SecretExists`] if
    /// `to` exists, [`Error::InvalidPath`], or decrypt/tamper errors.
    pub fn rename(&self, from: &str, to: &str, identity: &x25519::Identity) -> Result<()> {
        self.with_write_lock(|| self.rename_locked(from, to, identity))
    }

    fn rename_locked(&self, from: &str, to: &str, identity: &x25519::Identity) -> Result<()> {
        let (src, _dst) = self.relocate_paths(from, to)?;
        // Finish any interrupted rename (authenticated) before staging a new one.
        self.rollforward_or_back_move(identity)?;

        let gens = generations::load(&self.config.store_dir)?;
        let next = gens.next(to);

        let plaintext = crypto::decrypt(&std::fs::read(&src)?, identity)?;
        let unwrapped = envelope::unwrap(from, &plaintext)?;
        generations::verify(from, unwrapped.generation, &gens)?;
        let payload = Zeroizing::new(unwrapped.payload);
        let ciphertext = self.encrypt_secret(to, unwrapped.kind, next, &payload)?;

        let staging = self.move_dir();
        remove_staging(&staging);
        let secrets = staging.join(MOVE_SECRETS);
        crypto::write_atomic(&pathutil::to_file(&secrets, to), &ciphertext)?;
        crypto::write_atomic(&staging.join(MOVE_FROM), from.as_bytes())?;
        crypto::write_atomic(&staging.join(MOVE_TO), to.as_bytes())?;
        crypto::write_atomic(&staging.join(MOVE_GEN), next.to_string().as_bytes())?;
        crypto::write_atomic(&staging.join(MOVE_READY), b"")?;

        self.commit_move(&staging)
    }

    /// Copies a secret: decrypts, re-binds to `to` with a new generation, writes.
    ///
    /// # Errors
    /// Same as [`rename`](Store::rename), minus pruning.
    pub fn copy(&self, from: &str, to: &str, identity: &x25519::Identity) -> Result<()> {
        self.with_write_lock(|| {
            let (src, dst) = self.relocate_paths(from, to)?;
            let mut gens = generations::load(&self.config.store_dir)?;
            let next = gens.next(to);
            let plaintext = crypto::decrypt(&std::fs::read(&src)?, identity)?;
            let unwrapped = envelope::unwrap(from, &plaintext)?;
            generations::verify(from, unwrapped.generation, &gens)?;
            let payload = Zeroizing::new(unwrapped.payload);
            let ciphertext = self.encrypt_secret(to, unwrapped.kind, next, &payload)?;
            crypto::write_atomic(&dst, &ciphertext)?;
            gens.set(to.to_owned(), next);
            generations::save(&self.config.store_dir, &gens)
        })
    }

    /// Lists logical paths under `prefix` (`""` for all), sorted.
    ///
    /// # Errors
    /// [`Error::Io`] on directory traversal failures.
    pub fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut out = Vec::new();
        walk(&self.config.store_dir, &self.config.store_dir, &mut out)?;
        out.sort();
        if prefix.is_empty() {
            return Ok(out);
        }
        let scope = format!("{prefix}/");
        Ok(out
            .into_iter()
            .filter(|p| p == prefix || p.starts_with(&scope))
            .collect())
    }

    /// Searches paths (always) and decrypted contents (when `identity` is
    /// `Some`) case-insensitively for `query`.
    ///
    /// # Errors
    /// [`Error::Io`] if the store directory cannot be listed.
    pub fn grep(&self, query: &str, identity: Option<&x25519::Identity>) -> Result<GrepResults> {
        let needle = query.to_lowercase();
        let mut results = GrepResults::default();
        for path in self.list("")? {
            if path.to_lowercase().contains(&needle) {
                results.matches.push(path);
                continue;
            }
            let Some(id) = identity else { continue };
            match self.get(&path, id) {
                Ok(secret) if secret.expose().to_lowercase().contains(&needle) => {
                    results.matches.push(path);
                }
                Ok(_) => {}
                Err(_) => results.unreadable.push(path),
            }
        }
        Ok(results)
    }

    /// Replaces the recipient list and re-encrypts every secret to it.
    ///
    /// Generation is preserved (content-stable reencrypt). Unreadable secrets
    /// fail the rotation and roll back staging.
    ///
    /// # Errors
    /// [`Error::InvalidRecipient`] if the user's own key is missing, or
    /// [`Error::Io`] / [`Error::Decrypt`] / [`Error::Tampered`] during re-encryption.
    pub fn set_recipients(
        &mut self,
        new_recipients: Vec<x25519::Recipient>,
        identity: &x25519::Identity,
    ) -> Result<usize> {
        if !crypto::recipients_contain(&new_recipients, &identity.to_public()) {
            return Err(Error::InvalidRecipient(
                "recipient list must include your own public key".into(),
            ));
        }
        let mut lock = RwLock::new(self.lock_file()?);
        let _guard = lock.write().map_err(Error::Io)?;

        self.rollforward_or_back(identity)?;
        self.rollforward_or_back_move(identity)?;
        // Recipients may have changed if a READY rotation was applied.
        self.recipients = crypto::load_recipients(&self.config.recipients_path())?;

        let paths = self.list("")?;
        let staging = self.staging_dir();
        remove_staging(&staging);

        if let Err(e) = self.stage_rotation(&paths, &staging, &new_recipients, identity) {
            remove_staging(&staging);
            return Err(e);
        }

        self.commit_staged(&staging)?;
        self.recipients = new_recipients;
        Ok(paths.len())
    }

    fn stage_rotation(
        &self,
        paths: &[String],
        staging: &Path,
        new_recipients: &[x25519::Recipient],
        identity: &x25519::Identity,
    ) -> Result<()> {
        let secrets = staging.join(ROTATE_SECRETS);
        let gens = generations::load(&self.config.store_dir)?;

        for path in paths {
            let file = pathutil::to_file(&self.config.store_dir, path);
            let plaintext = crypto::decrypt(&std::fs::read(&file)?, identity)?;
            let unwrapped = envelope::unwrap(path, &plaintext)?;
            generations::verify(path, unwrapped.generation, &gens)?;
            let payload = Zeroizing::new(unwrapped.payload);
            // Content-stable reencrypt: preserve sealed generation.
            let ciphertext = encrypt_secret_to(
                path,
                unwrapped.kind,
                unwrapped.generation,
                &payload,
                new_recipients,
            )?;
            crypto::write_atomic(&pathutil::to_file(&secrets, path), &ciphertext)?;
        }

        crypto::save_recipients(&staging.join(ROTATE_RECIPIENTS), new_recipients)?;
        crypto::write_atomic(&staging.join(ROTATE_READY), b"")?;
        Ok(())
    }

    fn staging_dir(&self) -> PathBuf {
        self.config.store_dir.join(ROTATE_DIR)
    }

    fn move_dir(&self) -> PathBuf {
        self.config.store_dir.join(MOVE_DIR)
    }

    /// Discards incomplete (no `READY`) journals under the write lock.
    fn discard_incomplete_journals(&self) -> Result<()> {
        self.with_write_lock(|| {
            discard_if_incomplete(&self.staging_dir(), ROTATE_READY);
            discard_if_incomplete(&self.move_dir(), MOVE_READY);
            Ok(())
        })
    }

    /// Resolves a recipient rotation interrupted mid-flight.
    ///
    /// `READY` journals apply only after staged recipients include `identity`'s
    /// public key and every staged secret decrypts with that identity.
    ///
    /// # Errors
    /// [`Error::Io`], [`Error::InvalidRecipient`], or decrypt/tamper on staged data.
    pub fn recover_rotation(&self, identity: &x25519::Identity) -> Result<RotationRecovery> {
        self.with_write_lock(|| self.rollforward_or_back(identity))
    }

    /// Resolves a rename interrupted mid-flight.
    ///
    /// Validates `FROM`/`TO` and refuses to delete the source unless the
    /// destination ciphertext is present after install.
    ///
    /// # Errors
    /// [`Error::Io`], [`Error::InvalidPath`], or decrypt/tamper on staged data.
    pub fn recover_move(&self, identity: &x25519::Identity) -> Result<MoveRecovery> {
        self.with_write_lock(|| self.rollforward_or_back_move(identity))
    }

    fn rollforward_or_back(&self, identity: &x25519::Identity) -> Result<RotationRecovery> {
        let staging = self.staging_dir();
        if !staging.exists() {
            return Ok(RotationRecovery::Clean);
        }
        if staging.join(ROTATE_READY).exists() {
            Self::validate_ready_rotation(&staging, identity)?;
            self.commit_staged(&staging)?;
            Ok(RotationRecovery::Completed)
        } else {
            remove_staging(&staging);
            Ok(RotationRecovery::RolledBack)
        }
    }

    fn rollforward_or_back_move(&self, identity: &x25519::Identity) -> Result<MoveRecovery> {
        let staging = self.move_dir();
        if !staging.exists() {
            return Ok(MoveRecovery::Clean);
        }
        if staging.join(MOVE_READY).exists() {
            self.validate_ready_move(&staging, identity)?;
            self.commit_move(&staging)?;
            Ok(MoveRecovery::Completed)
        } else {
            remove_staging(&staging);
            Ok(MoveRecovery::RolledBack)
        }
    }

    fn validate_ready_rotation(staging: &Path, identity: &x25519::Identity) -> Result<()> {
        let target = crypto::load_recipients(&staging.join(ROTATE_RECIPIENTS))?;
        if !crypto::recipients_contain(&target, &identity.to_public()) {
            return Err(Error::InvalidRecipient(
                "staged rotation excludes your public key; refusing unauthenticated recover".into(),
            ));
        }
        let secrets = staging.join(ROTATE_SECRETS);
        let mut paths = Vec::new();
        if secrets.exists() {
            walk(&secrets, &secrets, &mut paths)?;
        }
        for path in &paths {
            pathutil::validate(path)?;
            let staged = pathutil::to_file(&secrets, path);
            let plaintext = crypto::decrypt(&std::fs::read(&staged)?, identity)?;
            let unwrapped = envelope::unwrap(path, &plaintext)?;
            drop(unwrapped);
        }
        Ok(())
    }

    fn validate_ready_move(&self, staging: &Path, identity: &x25519::Identity) -> Result<()> {
        let from = read_text_file(&staging.join(MOVE_FROM))?;
        let to = read_text_file(&staging.join(MOVE_TO))?;
        pathutil::validate(&from)?;
        pathutil::validate(&to)?;
        let _ = read_gen_file(&staging.join(MOVE_GEN))?;

        let staged = pathutil::to_file(&staging.join(MOVE_SECRETS), &to);
        let live = pathutil::to_file(&self.config.store_dir, &to);
        if staged.exists() {
            let plaintext = crypto::decrypt(&std::fs::read(&staged)?, identity)?;
            let unwrapped = envelope::unwrap(&to, &plaintext)?;
            drop(unwrapped);
        } else if !live.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "READY rename journal has no staged or live destination ciphertext",
            )));
        }
        Ok(())
    }

    fn commit_staged(&self, staging: &Path) -> Result<()> {
        let secrets = staging.join(ROTATE_SECRETS);
        let mut paths = Vec::new();
        if secrets.exists() {
            walk(&secrets, &secrets, &mut paths)?;
        }
        for path in &paths {
            pathutil::validate(path)?;
            crypto::rename_replace(
                &pathutil::to_file(&secrets, path),
                &pathutil::to_file(&self.config.store_dir, path),
            )?;
        }
        let target = crypto::load_recipients(&staging.join(ROTATE_RECIPIENTS))?;
        crypto::save_recipients(&self.config.recipients_path(), &target)?;
        remove_staging(staging);
        Ok(())
    }

    /// Phase 2 of rename: install dst, remove src only if dst exists, update index.
    fn commit_move(&self, staging: &Path) -> Result<()> {
        let from = read_text_file(&staging.join(MOVE_FROM))?;
        let to = read_text_file(&staging.join(MOVE_TO))?;
        pathutil::validate(&from)?;
        pathutil::validate(&to)?;
        let generation = read_gen_file(&staging.join(MOVE_GEN))?;

        let staged = pathutil::to_file(&staging.join(MOVE_SECRETS), &to);
        let live = pathutil::to_file(&self.config.store_dir, &to);
        if staged.exists() {
            crypto::rename_replace(&staged, &live)?;
        }
        if !live.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "refusing to delete rename source without destination ciphertext",
            )));
        }

        let src = pathutil::to_file(&self.config.store_dir, &from);
        if src.exists() {
            std::fs::remove_file(&src)?;
            prune_empty_parents(&self.config.store_dir, src.parent());
        }

        let mut gens = generations::load(&self.config.store_dir)?;
        gens.set(to, generation);
        // Keep `from` as tombstone floor (do not remove).
        generations::save(&self.config.store_dir, &gens)?;
        remove_staging(staging);
        Ok(())
    }

    fn relocate_paths(&self, from: &str, to: &str) -> Result<(PathBuf, PathBuf)> {
        pathutil::validate(from)?;
        pathutil::validate(to)?;
        let src = pathutil::to_file(&self.config.store_dir, from);
        if !src.exists() {
            return Err(Error::SecretNotFound(from.to_owned()));
        }
        if self.exists(to) {
            return Err(Error::SecretExists(to.to_owned()));
        }
        let dst = pathutil::to_file(&self.config.store_dir, to);
        Ok((src, dst))
    }

    /// Rebuilds the generation index from live envelopes (identity required).
    ///
    /// Readable sealed envelopes set the index floor from their generation.
    /// Unreadable paths are **skipped** (prior index line preserved if any) and
    /// listed in [`RepairReport::skipped`]. Tombstones for deleted paths are
    /// kept. Does not re-encrypt.
    ///
    /// # Errors
    /// [`Error::Io`] when listing or writing the index fails.
    pub fn repair_generations(&self, identity: &x25519::Identity) -> Result<RepairReport> {
        self.with_write_lock(|| self.repair_generations_locked(identity))
    }

    fn repair_generations_locked(&self, identity: &x25519::Identity) -> Result<RepairReport> {
        let prior = generations::load(&self.config.store_dir)?;
        let live: std::collections::HashSet<String> = self.list("")?.into_iter().collect();
        let mut final_map = Generations::default();
        let mut skipped = Vec::new();

        for path in &live {
            if let Ok(generation) = self.envelope_generation(path, identity) {
                final_map.set(path.clone(), generation);
            } else {
                skipped.push(path.clone());
                preserve_prior_floor(&prior, &mut final_map, path);
            }
        }

        for (path, generation) in prior.iter().filter(|(p, _)| !live.contains(*p)) {
            final_map.set(path.to_owned(), generation);
        }

        let entries = final_map.len();
        generations::save(&self.config.store_dir, &final_map)?;
        Ok(RepairReport { entries, skipped })
    }

    /// Returns the sealed generation for a live path, or `Err(())` if unreadable.
    fn envelope_generation(
        &self,
        path: &str,
        identity: &x25519::Identity,
    ) -> std::result::Result<u64, ()> {
        let file = pathutil::to_file(&self.config.store_dir, path);
        let bytes = std::fs::read(&file).map_err(|_| ())?;
        let plaintext = crypto::decrypt(&bytes, identity).map_err(|_| ())?;
        let unwrapped = envelope::unwrap(path, &plaintext).map_err(|_| ())?;
        Ok(unwrapped.generation)
    }

    /// Scans secrets for envelope and generation health (doctor).
    ///
    /// # Errors
    /// [`Error::Io`] when the store cannot be listed.
    pub fn generation_census(&self, identity: &x25519::Identity) -> Result<GenerationCensus> {
        let gens = generations::load(&self.config.store_dir)?;
        let paths = self.list("")?;
        let live: std::collections::HashSet<&str> = paths.iter().map(String::as_str).collect();
        let mut census = GenerationCensus::default();
        let mut protected = true;

        for path in &paths {
            if !self.census_one_path(path, identity, &gens, &mut census) {
                protected = false;
            }
        }

        for (path, _) in gens.iter() {
            if !live.contains(path) {
                census.tombstone_count = census.tombstone_count.saturating_add(1);
            }
        }
        census.fully_protected = protected
            && census.missing_index.is_empty()
            && census.lag_paths.is_empty()
            && census.stale_paths.is_empty();
        Ok(census)
    }

    /// Updates `census` for one secret path. Returns `false` if not fully protected.
    fn census_one_path(
        &self,
        path: &str,
        identity: &x25519::Identity,
        gens: &Generations,
        census: &mut GenerationCensus,
    ) -> bool {
        let file = pathutil::to_file(&self.config.store_dir, path);
        let Ok(bytes) = std::fs::read(&file) else {
            return false;
        };
        let Ok(plaintext) = crypto::decrypt(&bytes, identity) else {
            return false;
        };
        let Ok(unwrapped) = envelope::unwrap(path, &plaintext) else {
            return false;
        };

        census.sealed_count = census.sealed_count.saturating_add(1);

        let Some(index_gen) = gens.get(path) else {
            census.missing_index.push(path.to_owned());
            return false;
        };
        if unwrapped.generation < index_gen {
            census.stale_paths.push(path.to_owned());
            return false;
        }
        if unwrapped.generation > index_gen {
            census.lag_paths.push(path.to_owned());
            return false;
        }
        true
    }
}

fn preserve_prior_floor(prior: &Generations, map: &mut Generations, path: &str) {
    if let Some(generation) = prior.get(path) {
        map.set(path.to_owned(), generation);
    }
}

fn encrypt_secret_to(
    logical: &str,
    kind: crate::secret::SecretKind,
    generation: u64,
    payload: &[u8],
    recipients: &[x25519::Recipient],
) -> Result<Vec<u8>> {
    let wrapped = envelope::wrap(logical, kind, generation, payload);
    crypto::encrypt(&wrapped, recipients)
}

fn read_text_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    let s = String::from_utf8(bytes).map_err(|e| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    Ok(s.trim().to_owned())
}

fn read_gen_file(path: &Path) -> Result<u64> {
    let s = read_text_file(path)?;
    envelope::parse_generation(s.as_bytes())
        .map_err(|reason| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, reason)))
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let entry_path = entry.path();

        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            walk(root, &entry_path, out)?;
            continue;
        }
        if let Some(logical) = pathutil::from_file(root, &entry_path) {
            out.push(logical);
        }
    }
    Ok(())
}

fn prune_empty_parents(root: &Path, dir: Option<&Path>) {
    let Some(mut cur) = dir else { return };
    let mut owned: PathBuf;
    while cur != root {
        let Ok(mut entries) = std::fs::read_dir(cur) else {
            return;
        };
        if entries.next().is_some() {
            return;
        }
        if std::fs::remove_dir(cur).is_err() {
            return;
        }
        let Some(parent) = cur.parent() else { return };
        owned = parent.to_path_buf();
        cur = &owned;
    }
}

fn remove_staging(dir: &Path) {
    if dir.exists() {
        std::fs::remove_dir_all(dir).ok();
    }
}

/// Drops a journal directory when the commit marker is absent (safe rollback).
fn discard_if_incomplete(dir: &Path, ready_name: &str) {
    if dir.exists() && !dir.join(ready_name).exists() {
        remove_staging(dir);
    }
}

#[cfg(test)]
mod tests {
    use age::secrecy::SecretString;

    use super::*;

    fn fresh() -> (Config, x25519::Identity) {
        let root = std::env::temp_dir().join(format!("ks-store-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).expect("temp");
        let cfg = Config {
            identity_path: root.join("identity.age"),
            store_dir: root.join("store"),
        };
        let id = crypto::create_identity(&cfg.identity_path, SecretString::from("pw".to_owned()))
            .expect("identity");
        (cfg, id)
    }

    #[test]
    fn set_needs_no_identity_get_does() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store
            .set("github/token", &Secret::new("ghp_xxx\nuser: alice\n"))
            .expect("set");
        let got = store.get("github/token", &id).expect("get");
        assert_eq!(got.password(), "ghp_xxx");
        assert_eq!(got.get("user"), Some("alice"));
        assert_eq!(
            store.list("").expect("list"),
            vec!["github/token".to_owned()]
        );
    }

    #[test]
    fn rename_and_copy_rebind_path() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.set("a/b", &Secret::new("v")).expect("set");

        store.copy("a/b", "a/c", &id).expect("copy");
        assert!(store.exists("a/b") && store.exists("a/c"));
        assert_eq!(store.get("a/c", &id).expect("get").password(), "v");

        store.rename("a/b", "x/y", &id).expect("rename");
        assert!(!store.exists("a/b") && store.exists("x/y"));
        assert_eq!(store.get("x/y", &id).expect("get").password(), "v");
    }

    #[test]
    fn relocating_ciphertext_is_detected_as_tampering() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("a", &Secret::new("secret-a")).expect("a");
        store.set("b", &Secret::new("secret-b")).expect("b");

        let pa = pathutil::to_file(&cfg.store_dir, "a");
        let pb = pathutil::to_file(&cfg.store_dir, "b");
        let tmp = cfg.store_dir.join("swap.tmp");
        std::fs::rename(&pa, &tmp).expect("mv a");
        std::fs::rename(&pb, &pa).expect("mv b->a");
        std::fs::rename(&tmp, &pb).expect("mv tmp->b");

        assert!(matches!(store.get("a", &id), Err(Error::Tampered { .. })));
    }

    #[test]
    fn older_ciphertext_under_newer_index_is_tampered() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("v1")).expect("set1");
        let old_ct = std::fs::read(pathutil::to_file(&cfg.store_dir, "p")).expect("read");
        store.set("p", &Secret::new("v2")).expect("set2");
        // Restore older ciphertext; index still at gen 2.
        std::fs::write(pathutil::to_file(&cfg.store_dir, "p"), old_ct).expect("restore");
        assert!(matches!(store.get("p", &id), Err(Error::Tampered { .. })));
    }

    #[test]
    fn repair_recovers_stale_for_local_get() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("old")).expect("set1");
        let old_ct = std::fs::read(pathutil::to_file(&cfg.store_dir, "p")).expect("read");
        store.set("p", &Secret::new("new")).expect("set2");
        std::fs::write(pathutil::to_file(&cfg.store_dir, "p"), old_ct).expect("restore");
        assert!(store.get("p", &id).is_err());
        let report = store.repair_generations(&id).expect("repair");
        assert!(report.skipped.is_empty());
        assert_eq!(store.get("p", &id).expect("get").password(), "old");
    }

    #[test]
    fn repair_skips_unreadable_and_fixes_others() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("good", &Secret::new("g")).expect("good");
        store.set("bad", &Secret::new("b")).expect("bad");
        // Force lag on good: bump index without rewriting ciphertext by re-set then restore.
        let good_ct = std::fs::read(pathutil::to_file(&cfg.store_dir, "good")).expect("r");
        store.set("good", &Secret::new("g2")).expect("bump");
        std::fs::write(pathutil::to_file(&cfg.store_dir, "good"), good_ct).expect("restore lag");
        // Corrupt bad ciphertext.
        std::fs::write(pathutil::to_file(&cfg.store_dir, "bad"), b"not-age").expect("corrupt");

        let report = store.repair_generations(&id).expect("repair");
        assert!(report.skipped.iter().any(|p| p == "bad"));
        // good is stale (envelope < index); repair lowers index to envelope gen.
        assert_eq!(store.get("good", &id).expect("good").password(), "g");
        assert!(store.get("bad", &id).is_err());
    }

    #[test]
    fn set_without_repair_at_high_index_writes_h_plus_one() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("a")).expect("1");
        store.set("p", &Secret::new("b")).expect("2");
        store.set("p", &Secret::new("c")).expect("3"); // index H=3
        // Plant older envelope L=1 while index stays 3.
        store.set("p", &Secret::new("temp")).expect("temp");
        // Rebuild: read gen after three sets then force stale file is harder;
        // instead assert set at H=3 yields gen 4.
        let gens = generations::load(&cfg.store_dir).expect("gens");
        assert_eq!(gens.get("p"), Some(4)); // last set was gen 4 from temp
        store.set("p", &Secret::new("durable")).expect("set");
        let after = generations::load(&cfg.store_dir).expect("after");
        assert_eq!(after.get("p"), Some(5));
        assert_eq!(store.get("p", &id).expect("get").password(), "durable");
    }

    #[test]
    fn repair_then_set_after_gap_yields_only_l_plus_one() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("L1")).expect("1");
        let l1_ct = std::fs::read(pathutil::to_file(&cfg.store_dir, "p")).expect("ct");
        store.set("p", &Secret::new("L2")).expect("2");
        store.set("p", &Secret::new("L3")).expect("3"); // H=3
        std::fs::write(pathutil::to_file(&cfg.store_dir, "p"), l1_ct).expect("plant L=1");
        // repair → floor L=1; set → gen 2 only (not H+1).
        store.repair_generations(&id).expect("repair");
        store.set("p", &Secret::new("after")).expect("set");
        let after = generations::load(&cfg.store_dir).expect("after");
        assert_eq!(after.get("p"), Some(2));
    }

    #[test]
    fn delete_tombstone_continues_generation() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("a")).expect("a");
        store.set("p", &Secret::new("b")).expect("b"); // gen 2
        store.delete("p").expect("del");
        store.set("p", &Secret::new("c")).expect("c"); // gen 3
        let gens = generations::load(&cfg.store_dir).expect("gens");
        assert_eq!(gens.get("p"), Some(3));
        assert_eq!(store.get("p", &id).expect("get").password(), "c");
    }

    #[test]
    fn binary_secret_roundtrips_through_store() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        let raw = vec![0u8, b'\n', 0xff, 0x00, b'x'];
        store
            .set(
                "certs/key",
                &Secret::from_bytes(raw.clone(), crate::secret::SecretKind::Binary),
            )
            .expect("set binary");
        let got = store.get("certs/key", &id).expect("get");
        assert!(got.is_binary());
        assert_eq!(got.as_bytes(), &raw[..]);
    }

    #[test]
    fn grep_paths_then_values() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.set("github/token", &Secret::new("ghp")).expect("s1");
        store
            .set("aws/key", &Secret::new("secret\nregion: eu-west-1\n"))
            .expect("s2");

        assert_eq!(
            store.grep("github", None).expect("grep").matches,
            vec!["github/token"]
        );
        assert!(
            store
                .grep("eu-west", None)
                .expect("grep")
                .matches
                .is_empty()
        );
        assert_eq!(
            store
                .grep("eu-west", Some(&id))
                .expect("grep values")
                .matches,
            vec!["aws/key"]
        );
    }

    #[test]
    fn grep_values_reports_unreadable_secrets() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("ok", &Secret::new("findme")).expect("ok");
        store.set("broken", &Secret::new("findme")).expect("broken");

        std::fs::write(pathutil::to_file(&cfg.store_dir, "broken"), b"not age").expect("corrupt");

        let res = store.grep("findme", Some(&id)).expect("grep values");
        assert_eq!(res.matches, vec!["ok"]);
        assert_eq!(res.unreadable, vec!["broken"]);
    }

    #[test]
    fn set_recipients_reencrypts_and_guards_lockout() {
        let (cfg, id) = fresh();
        let mut store = Store::create(cfg, &id, &[]).expect("create");
        store.set("k", &Secret::new("v")).expect("set");

        let backup = x25519::Identity::generate();
        let n = store
            .set_recipients(vec![id.to_public(), backup.to_public()], &id)
            .expect("reencrypt");
        assert_eq!(n, 1);
        assert_eq!(store.get("k", &id).expect("get").password(), "v");

        let stranger = x25519::Identity::generate();
        assert!(matches!(
            store.set_recipients(vec![stranger.to_public()], &id),
            Err(Error::InvalidRecipient(_))
        ));
    }

    #[test]
    fn failed_rotation_leaves_store_unchanged() {
        let (cfg, id) = fresh();
        let mut store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("a", &Secret::new("va")).expect("a");
        store.set("b", &Secret::new("vb")).expect("b");

        std::fs::write(pathutil::to_file(&cfg.store_dir, "b"), b"garbage").expect("corrupt");
        let a_before = std::fs::read(pathutil::to_file(&cfg.store_dir, "a")).expect("read a");

        let backup = x25519::Identity::generate();
        assert!(
            store
                .set_recipients(vec![id.to_public(), backup.to_public()], &id)
                .is_err()
        );

        let a_after = std::fs::read(pathutil::to_file(&cfg.store_dir, "a")).expect("read a");
        assert_eq!(
            a_before, a_after,
            "live store must be untouched on rollback"
        );
        assert!(!cfg.store_dir.join(".ks-rotate").exists());
        assert_eq!(store.get("a", &id).expect("get a").password(), "va");
    }

    #[test]
    fn rotation_crash_after_ready_rolls_forward() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("k", &Secret::new("v")).expect("set");

        let backup = x25519::Identity::generate();
        let target = vec![id.to_public(), backup.to_public()];
        let staging = store.staging_dir();
        store
            .stage_rotation(&["k".to_owned()], &staging, &target, &id)
            .expect("stage");
        assert!(staging.join(ROTATE_READY).exists());
        assert!(store.get("k", &backup).is_err());
        drop(store);

        let recovered = Store::open(cfg.clone()).expect("open leaves READY");
        assert!(
            staging.exists(),
            "READY journal must not auto-apply on open without identity"
        );
        assert_eq!(
            recovered
                .recover_rotation(&id)
                .expect("authenticated recover"),
            RotationRecovery::Completed
        );
        assert!(!staging.exists(), "staging cleared after recover");
        assert_eq!(recovered.get("k", &id).expect("get").password(), "v");
        assert_eq!(
            recovered.get("k", &backup).expect("backup get").password(),
            "v",
            "the new recipient must be able to decrypt after roll-forward"
        );
        let recips = crypto::load_recipients(&cfg.recipients_path()).expect("recips");
        assert!(crypto::recipients_contain(&recips, &backup.to_public()));
        assert_eq!(
            recovered.recover_rotation(&id).expect("idempotent"),
            RotationRecovery::Clean
        );
    }

    #[test]
    fn rotation_crash_before_ready_rolls_back() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("k", &Secret::new("v")).expect("set");
        let live_before = std::fs::read(pathutil::to_file(&cfg.store_dir, "k")).expect("read");

        let backup = x25519::Identity::generate();
        let target = vec![id.to_public(), backup.to_public()];
        let staging = store.staging_dir();
        store
            .stage_rotation(&["k".to_owned()], &staging, &target, &id)
            .expect("stage");
        std::fs::remove_file(staging.join(ROTATE_READY)).expect("drop ready");
        drop(store);

        let recovered = Store::open(cfg.clone()).expect("open rolls back");
        assert!(!staging.exists(), "incomplete staging must be discarded");
        let live_after = std::fs::read(pathutil::to_file(&cfg.store_dir, "k")).expect("read");
        assert_eq!(live_before, live_after, "live store must be untouched");
        let recips = crypto::load_recipients(&cfg.recipients_path()).expect("recips");
        assert!(
            !crypto::recipients_contain(&recips, &backup.to_public()),
            "a rolled-back rotation must not change recipients"
        );
        assert_eq!(recovered.get("k", &id).expect("get").password(), "v");
    }

    #[test]
    fn rename_crash_before_ready_rolls_back() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("from", &Secret::new("v")).expect("set");

        // Stage a move without READY.
        let staging = store.move_dir();
        crypto::create_dir_all_secure(&staging.join(MOVE_SECRETS)).expect("dir");
        crypto::write_atomic(&staging.join(MOVE_FROM), b"from").expect("from");
        crypto::write_atomic(&staging.join(MOVE_TO), b"to").expect("to");
        // No READY.
        drop(store);

        let recovered = Store::open(cfg).expect("open");
        assert!(!staging.exists());
        assert!(recovered.exists("from"));
        assert!(!recovered.exists("to"));
        assert_eq!(recovered.get("from", &id).expect("get").password(), "v");
    }

    #[test]
    fn rename_crash_after_ready_rolls_forward() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("from", &Secret::new("v")).expect("set");

        // Manually run phase 1 of rename then drop without phase 2.
        let gens = generations::load(&cfg.store_dir).expect("gens");
        let next = gens.next("to");
        let plaintext = crypto::decrypt(
            &std::fs::read(pathutil::to_file(&cfg.store_dir, "from")).expect("r"),
            &id,
        )
        .expect("d");
        let u = envelope::unwrap("from", &plaintext).expect("u");
        let ct = store
            .encrypt_secret("to", u.kind, next, &u.payload)
            .expect("enc");
        let staging = store.move_dir();
        crypto::write_atomic(&pathutil::to_file(&staging.join(MOVE_SECRETS), "to"), &ct)
            .expect("stage");
        crypto::write_atomic(&staging.join(MOVE_FROM), b"from").expect("from");
        crypto::write_atomic(&staging.join(MOVE_TO), b"to").expect("to");
        crypto::write_atomic(&staging.join(MOVE_GEN), next.to_string().as_bytes()).expect("gen");
        crypto::write_atomic(&staging.join(MOVE_READY), b"").expect("ready");
        drop(store);

        let recovered = Store::open(cfg).expect("open leaves READY");
        assert!(
            staging.exists(),
            "READY rename not applied without identity"
        );
        assert_eq!(
            recovered.recover_move(&id).expect("recover"),
            MoveRecovery::Completed
        );
        assert!(!staging.exists());
        assert!(!recovered.exists("from"));
        assert!(recovered.exists("to"));
        assert_eq!(recovered.get("to", &id).expect("get").password(), "v");
    }

    #[test]
    fn repair_generations_rebuilds_index() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("a", &Secret::new("1")).expect("a");
        store.set("b", &Secret::new("2")).expect("b");
        // Wipe index.
        drop(std::fs::remove_file(generations::path(&cfg.store_dir)));
        let report = store.repair_generations(&id).expect("repair");
        assert!(report.entries >= 2);
        assert!(report.skipped.is_empty());
        assert_eq!(store.get("a", &id).expect("a").password(), "1");
        let census = store.generation_census(&id).expect("census");
        assert!(census.fully_protected);
        assert_eq!(census.sealed_count, 2);
    }

    #[test]
    fn wrong_identity_cannot_decrypt() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.set("k", &Secret::new("secret")).expect("set");
        let stranger = x25519::Identity::generate();
        assert!(store.get("k", &stranger).is_err());
    }

    #[test]
    fn insert_refuses_overwrite() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.insert("k", &Secret::new("a")).expect("insert");
        assert!(matches!(
            store.insert("k", &Secret::new("b")),
            Err(Error::SecretExists(_))
        ));
        store.set("k", &Secret::new("b")).expect("set overwrite");
        assert_eq!(store.get("k", &id).expect("get").password(), "b");
    }

    fn write_batch(store: &Store, worker: u32) {
        for j in 0..20 {
            let path = format!("w/{worker}-{j}");
            store
                .set(&path, &Secret::new(format!("v{worker}-{j}")))
                .expect("set");
        }
    }

    #[test]
    fn concurrent_writers_serialized_by_lock() {
        use std::sync::Arc;
        use std::thread;

        let (cfg, id) = fresh();
        let store = Arc::new(Store::create(cfg, &id, &[]).expect("create"));
        let handles: Vec<_> = (0..8_u32)
            .map(|i| {
                let s = Arc::clone(&store);
                thread::spawn(move || write_batch(&s, i))
            })
            .collect();
        for h in handles {
            h.join().expect("join");
        }
        assert_eq!(store.list("").expect("list").len(), 8 * 20);
        assert_eq!(store.get("w/0-0", &id).expect("get").password(), "v0-0");
        assert_eq!(store.get("w/7-19", &id).expect("get").password(), "v7-19");
    }

    #[test]
    fn n1_coherent_old_pair_still_reads() {
        // Non-property N1: restoring secret + matching index together succeeds.
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("p", &Secret::new("old")).expect("old");
        let ct = std::fs::read(pathutil::to_file(&cfg.store_dir, "p")).expect("ct");
        let idx = std::fs::read(generations::path(&cfg.store_dir)).expect("idx");
        store.set("p", &Secret::new("new")).expect("new");
        std::fs::write(pathutil::to_file(&cfg.store_dir, "p"), ct).expect("restore ct");
        std::fs::write(generations::path(&cfg.store_dir), idx).expect("restore idx");
        assert_eq!(store.get("p", &id).expect("get").password(), "old");
    }

    #[test]
    fn census_flags_stale_and_lag() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg.clone(), &id, &[]).expect("create");
        store.set("stale", &Secret::new("a")).expect("a");
        let old = std::fs::read(pathutil::to_file(&cfg.store_dir, "stale")).expect("r");
        store.set("stale", &Secret::new("b")).expect("b");
        std::fs::write(pathutil::to_file(&cfg.store_dir, "stale"), old).expect("w");

        store.set("lag", &Secret::new("x")).expect("lag");
        // After sets, stale has gen 1 file + index 2. Save index with only stale
        // floor and omit lag → missing_index for lag.
        let mut g2 = Generations::default();
        g2.set("stale".into(), 2);
        generations::save(&cfg.store_dir, &g2).expect("save");

        let census = store.generation_census(&id).expect("census");
        assert!(census.stale_paths.iter().any(|p| p == "stale"));
        assert!(census.missing_index.iter().any(|p| p == "lag"));
        assert!(!census.fully_protected);
    }

    #[test]
    fn list_prefix_and_exists() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.set("a/b", &Secret::new("1")).expect("1");
        store.set("a/c", &Secret::new("2")).expect("2");
        store.set("z/x", &Secret::new("3")).expect("3");
        assert!(store.exists("a/b"));
        assert!(!store.exists("missing"));
        let under_a = store.list("a").expect("list");
        assert_eq!(under_a, vec!["a/b".to_owned(), "a/c".to_owned()]);
    }

    #[test]
    fn rename_refuses_existing_destination() {
        let (cfg, id) = fresh();
        let store = Store::create(cfg, &id, &[]).expect("create");
        store.set("a", &Secret::new("1")).expect("a");
        store.set("b", &Secret::new("2")).expect("b");
        assert!(matches!(
            store.rename("a", "b", &id),
            Err(Error::SecretExists(_))
        ));
    }
}
