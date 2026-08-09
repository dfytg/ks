//! Per-path generation index (`.ks-generations`).
//!
//! The index is a plain, git-synced text file of `path generation` lines. It is
//! **not** secret material. Combined with envelope generations it implements
//! property **P1**: reject decrypted envelope gen *N* when the index records *M*
//! with *N < M* (older ciphertext under a newer index).
//!
//! **Non-property N1:** restoring a coherent older pair of (secret file + matching
//! index line), or an entire older git commit of the store, is not detected.
//!
//! ## Multi-device merge
//!
//! `.gitattributes` sets `merge=union`. On load, duplicate paths keep
//! **max(generation)**. Concurrent disjoint-path writes merge without conflicts.
//!
//! ## Delete tombstones
//!
//! Deleting a secret removes the file but **keeps** the index line as a floor so
//! a later insert continues above the prior generation (avoids false Tampered
//! after multi-device delete+reinsert under max-reduce).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::crypto;
use crate::envelope;
use crate::error::{Error, Result};
use crate::path as pathutil;

/// Filename of the generation index at the store root.
pub(crate) const GENERATIONS_FILE: &str = ".ks-generations";

/// In-memory generation map (sorted on save via [`BTreeMap`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Generations {
    /// Path → generation (including tombstones for deleted paths).
    map: BTreeMap<String, u64>,
}

impl Generations {
    /// Returns the recorded generation for `path`, if any.
    #[must_use]
    pub(crate) fn get(&self, path: &str) -> Option<u64> {
        self.map.get(path).copied()
    }

    /// Sets `path` to `generation` (overwrite).
    pub(crate) fn set(&mut self, path: String, generation: u64) {
        self.map.insert(path, generation);
    }

    /// Next generation for a write: `current.unwrap_or(0) + 1` (saturating).
    #[must_use]
    pub(crate) fn next(&self, path: &str) -> u64 {
        self.map.get(path).copied().unwrap_or(0).saturating_add(1)
    }

    /// Number of index entries (including tombstones).
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Iterates path → generation in sorted order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&str, u64)> {
        self.map.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

/// Absolute path of the generations file under `store_dir`.
#[must_use]
pub(crate) fn path(store_dir: &Path) -> PathBuf {
    store_dir.join(GENERATIONS_FILE)
}

/// Loads and max-reduces the index. Missing file → empty map.
///
/// # Errors
/// [`Error::Io`] on read failure (other than not-found).
pub(crate) fn load(store_dir: &Path) -> Result<Generations> {
    let p = path(store_dir);
    let bytes = match std::fs::read(&p) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Generations::default());
        }
        Err(e) => return Err(Error::Io(e)),
    };
    Ok(parse(&bytes))
}

/// Atomically writes the canonical index (sorted, unique paths).
///
/// # Errors
/// [`Error::Io`] on write failure.
pub(crate) fn save(store_dir: &Path, gens: &Generations) -> Result<()> {
    let mut body =
        String::from("# ks generations — path generation pairs; written by ks under write lock\n");
    for (path, generation) in gens.iter() {
        body.push_str(path);
        body.push(' ');
        body.push_str(&generation.to_string());
        body.push('\n');
    }
    crypto::write_atomic(&path(store_dir), body.as_bytes())
}

/// Parses index bytes with max-reduce for duplicate paths.
#[must_use]
pub(crate) fn parse(bytes: &[u8]) -> Generations {
    let mut map: BTreeMap<String, u64> = BTreeMap::new();
    for line in bytes.split(|&b| b == b'\n') {
        let line = trim_ascii(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let Some((path_bytes, gen_bytes)) = split_two_tokens(line) else {
            continue;
        };
        let Ok(path) = std::str::from_utf8(path_bytes) else {
            continue;
        };
        if pathutil::validate(path).is_err() {
            continue;
        }
        let Ok(generation) = envelope::parse_generation(gen_bytes) else {
            continue;
        };
        map.entry(path.to_owned())
            .and_modify(|g| *g = (*g).max(generation))
            .or_insert(generation);
    }
    Generations { map }
}

/// Verifies envelope generation against the index (asymmetric P1 check).
///
/// | Condition | Result |
/// | --- | --- |
/// | path absent from index | Accept (missing-index weak mode) |
/// | envelope.gen < index.gen | [`Error::Tampered`] (P1) |
/// | envelope.gen ≥ index.gen | Accept (equality healthy; greater = lag) |
pub(crate) fn verify(logical: &str, envelope_gen: u64, index: &Generations) -> Result<()> {
    let Some(index_gen) = index.get(logical) else {
        return Ok(());
    };

    if envelope_gen < index_gen {
        return Err(Error::Tampered {
            path: logical.to_owned(),
            reason: format!(
                "envelope generation {envelope_gen} is older than index generation {index_gen}"
            ),
        });
    }
    Ok(())
}

fn split_two_tokens(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut parts = line
        .split(u8::is_ascii_whitespace)
        .filter(|p| !p.is_empty());
    let a = parts.next()?;
    let b = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    Some((a, b))
}

fn trim_ascii(mut s: &[u8]) -> &[u8] {
    while s.first().is_some_and(u8::is_ascii_whitespace) {
        s = s.get(1..).unwrap_or_default();
    }
    while s.last().is_some_and(u8::is_ascii_whitespace) {
        s = s.get(..s.len().saturating_sub(1)).unwrap_or_default();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_reduce_duplicates() {
        let g = parse(b"a/b 1\na/b 5\nc 2\n# comment\n");
        assert_eq!(g.get("a/b"), Some(5));
        assert_eq!(g.get("c"), Some(2));
        assert_eq!(g.next("a/b"), 6);
        assert_eq!(g.next("new"), 1);
    }

    #[test]
    fn verify_p1_and_lag() {
        let mut g = Generations::default();
        g.set("p".into(), 3);
        assert!(verify("p", 3, &g).is_ok());
        assert!(verify("p", 4, &g).is_ok()); // lag
        assert!(verify("p", 2, &g).is_err());
        assert!(verify("missing", 1, &g).is_ok());
    }

    #[test]
    fn gen_zero_under_positive_index_is_tampered() {
        let mut g = Generations::default();
        g.set("p".into(), 1);
        assert!(verify("p", 0, &g).is_err());
    }

    #[test]
    fn roundtrip_save_load() {
        let root = std::env::temp_dir().join(format!("ks-gen-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&root).expect("dir");
        let mut g = Generations::default();
        g.set("github/token".into(), 3);
        g.set("aws/key".into(), 1);
        save(&root, &g).expect("save");
        let loaded = load(&root).expect("load");
        assert_eq!(loaded, g);
        drop(std::fs::remove_dir_all(&root));
    }

    #[test]
    fn soak_random_parse_does_not_panic() {
        for _ in 0..2_000 {
            let n = usize::from(rand::random::<u8>());
            let mut buf = vec![0u8; n];
            for b in &mut buf {
                *b = rand::random();
            }
            drop(parse(&buf));
        }
        // Near-structured lines: path-like tokens + junk gens.
        for _ in 0..200 {
            let line = format!(
                "a/b {}\ninvalid line\n# comment\nc {}\n",
                rand::random::<u32>(),
                rand::random::<u64>()
            );
            drop(parse(line.as_bytes()));
        }
    }
}
