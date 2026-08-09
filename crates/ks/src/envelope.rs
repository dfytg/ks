//! Versioned secret envelope: binds path and generation into the ciphertext.
//!
//! Before encryption, a secret's bytes are wrapped with a small header that
//! records the format identifier, the secret kind, the logical path, and a
//! monotonic generation. After decryption the header is verified: path mismatch
//! yields [`Error::Tampered`]. Generation is checked against the store's
//! `.ks-generations` index by the store layer (see [`crate::generations`]).
//!
//! **Property P2 (path binding):** relocating or swapping ciphertext files is
//! rejected on read.
//!
//! **Property P1 (temporal, partial):** older ciphertext under a newer index
//! generation is rejected. Restoring a coherent older pair of (secret + matching
//! index line), or an entire older git commit, is **not** detected — permanent
//! non-property N1 (same class as intentional restore).
//!
//! Sole accepted layout (`ksenv/2` — the `/2` digit is a historical format
//! label, not a multi-version reader):
//!
//! ```text
//! ksenv/2
//! text
//! github/token
//! 3
//!
//! <payload bytes…>
//! ```

use std::str::FromStr as _;

use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::SecretKind;

/// Format magic. `/2` is historical; this is the only accepted identifier.
const MAGIC: &[u8] = b"ksenv/2\n";

const TAG_TEXT: &[u8] = b"text";
const TAG_BINARY: &[u8] = b"binary";

/// Result of successfully unwrapping an envelope.
#[derive(Debug)]
pub(crate) struct Unwrapped {
    /// Text vs binary payload semantics.
    pub kind: SecretKind,
    /// Monotonic generation sealed at write time.
    pub generation: u64,
    /// Secret payload bytes (not zeroized; caller wraps as needed).
    pub payload: Vec<u8>,
}

/// Wraps `payload` in a `ksenv/2` envelope bound to `logical`, `kind`, and `generation`.
///
/// The result is held in a [`Zeroizing`] buffer so the assembled plaintext is
/// scrubbed once it has been handed to the encryptor.
#[must_use]
pub(crate) fn wrap(
    logical: &str,
    kind: SecretKind,
    generation: u64,
    payload: &[u8],
) -> Zeroizing<Vec<u8>> {
    let tag = match kind {
        SecretKind::Text => TAG_TEXT,
        SecretKind::Binary => TAG_BINARY,
    };
    let gen_str = generation.to_string();
    let mut out = Zeroizing::new(Vec::with_capacity(
        MAGIC.len() + tag.len() + logical.len() + gen_str.len() + payload.len() + 4,
    ));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(tag);
    out.push(b'\n');
    out.extend_from_slice(logical.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(gen_str.as_bytes());
    out.push(b'\n');
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

/// Unwraps an envelope, verifying magic and that the bound path matches
/// `expected`. Only `ksenv/2` is accepted.
///
/// # Errors
/// Returns [`Error::Tampered`] if the header is missing or unsupported, the
/// bound path does not match, or a generation line is malformed.
pub(crate) fn unwrap(expected: &str, plaintext: &[u8]) -> Result<Unwrapped> {
    let tampered = |reason: String| Error::Tampered {
        path: expected.to_owned(),
        reason,
    };

    let rest = plaintext.strip_prefix(MAGIC).ok_or_else(|| {
        tampered("missing or unsupported envelope header (corrupt or legacy secret)".to_owned())
    })?;

    let (tag, rest) =
        split_line(rest).ok_or_else(|| tampered("truncated envelope header".to_owned()))?;
    let kind = match tag {
        TAG_TEXT => SecretKind::Text,
        TAG_BINARY => SecretKind::Binary,
        _ => return Err(tampered("unknown secret kind in envelope".to_owned())),
    };

    let (path_line, rest) =
        split_line(rest).ok_or_else(|| tampered("truncated envelope header".to_owned()))?;
    if path_line != expected.as_bytes() {
        return Err(tampered(format!(
            "bound path `{}` does not match its location",
            String::from_utf8_lossy(path_line)
        )));
    }

    let (gen_line, rest) =
        split_line(rest).ok_or_else(|| tampered("truncated envelope header".to_owned()))?;
    let generation = parse_generation(gen_line).map_err(tampered)?;
    let payload = rest
        .strip_prefix(b"\n")
        .ok_or_else(|| tampered("malformed envelope (missing header terminator)".to_owned()))?;

    Ok(Unwrapped {
        kind,
        generation,
        payload: payload.to_vec(),
    })
}

/// Parses a generation token: ASCII digits only, `u64::from_str`, no signs.
pub(crate) fn parse_generation(bytes: &[u8]) -> std::result::Result<u64, String> {
    if bytes.is_empty() {
        return Err("empty generation".to_owned());
    }
    if !bytes.iter().all(u8::is_ascii_digit) {
        return Err(format!(
            "invalid generation `{}`",
            String::from_utf8_lossy(bytes)
        ));
    }
    let s = std::str::from_utf8(bytes).map_err(|_| "invalid generation encoding".to_owned())?;
    u64::from_str(s).map_err(|_| format!("generation overflow `{s}`"))
}

fn split_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let idx = bytes.iter().position(|&c| c == b'\n')?;
    let line = bytes.get(..idx)?;
    let rest = bytes.get(idx.saturating_add(1)..)?;
    Some((line, rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_roundtrip() {
        let wrapped = wrap(
            "github/token",
            SecretKind::Text,
            3,
            b"ghp_xxx\nuser: alice\n",
        );
        let u = unwrap("github/token", &wrapped).expect("unwrap");
        assert_eq!(u.kind, SecretKind::Text);
        assert_eq!(u.generation, 3);
        assert_eq!(&u.payload, b"ghp_xxx\nuser: alice\n");
    }

    #[test]
    fn binary_roundtrip_with_arbitrary_bytes() {
        let raw = vec![0u8, b'\n', 0xff, b'k', b's', 0x00, 0x0a];
        let wrapped = wrap("certs/key.p12", SecretKind::Binary, 1, &raw);
        let u = unwrap("certs/key.p12", &wrapped).expect("unwrap");
        assert_eq!(u.kind, SecretKind::Binary);
        assert_eq!(u.generation, 1);
        assert_eq!(u.payload, raw);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let wrapped = wrap("a/b", SecretKind::Text, 1, b"");
        let u = unwrap("a/b", &wrapped).expect("unwrap");
        assert_eq!(u.kind, SecretKind::Text);
        assert!(u.payload.is_empty());
    }

    #[test]
    fn wrong_bound_path_is_tampered() {
        let wrapped = wrap("a", SecretKind::Text, 1, b"secret-a");
        let err = unwrap("b", &wrapped).expect_err("must reject");
        assert!(matches!(err, Error::Tampered { .. }));
    }

    #[test]
    fn legacy_or_corrupt_payload_is_tampered() {
        let err = unwrap("a", b"just a raw secret\n").expect_err("must reject");
        assert!(matches!(err, Error::Tampered { .. }));
    }

    #[test]
    fn legacy_v1_header_is_tampered() {
        let mut v1 = Vec::new();
        v1.extend_from_slice(b"ksenv/1\ntext\na\n\npayload");
        let err = unwrap("a", &v1).expect_err("v1 rejected");
        assert!(matches!(err, Error::Tampered { .. }));
    }

    #[test]
    fn payload_may_contain_header_like_lines() {
        let body = b"ksenv/2\ntext\nelsewhere\n9\n\nreal payload";
        let wrapped = wrap("real/path", SecretKind::Binary, 2, body);
        let u = unwrap("real/path", &wrapped).expect("unwrap");
        assert_eq!(u.kind, SecretKind::Binary);
        assert_eq!(&u.payload, body);
    }

    #[test]
    fn reject_bad_generation_tokens() {
        assert!(parse_generation(b"").is_err());
        assert!(parse_generation(b"+1").is_err());
        assert!(parse_generation(b"01x").is_err());
        assert!(parse_generation(b" 1").is_err());
        assert_eq!(parse_generation(b"0").expect("0"), 0);
        assert_eq!(parse_generation(b"42").expect("42"), 42);
    }

    #[test]
    fn malformed_generation_is_tampered() {
        let mut bad = Vec::new();
        bad.extend_from_slice(MAGIC);
        bad.extend_from_slice(b"text\na\n+3\n\npayload");
        let err = unwrap("a", &bad).expect_err("must reject");
        assert!(matches!(err, Error::Tampered { .. }));
    }

    /// Stable soak: random inputs must never panic (correctness pressure without
    /// cargo-fuzz/nightly).
    #[test]
    fn soak_random_inputs_do_not_panic() {
        for _ in 0..2_000 {
            let n = usize::from(rand::random::<u8>());
            let mut buf = vec![0u8; n];
            for b in &mut buf {
                *b = rand::random();
            }
            drop(unwrap("fuzz/path", &buf));
        }
        // Structured near-misses: valid magic, garbage body.
        for _ in 0..200 {
            let mut buf = MAGIC.to_vec();
            let n = usize::from(rand::random::<u8>() % 64);
            buf.extend((0..n).map(|_| rand::random::<u8>()));
            drop(unwrap("a", &buf));
        }
    }
}
