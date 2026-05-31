//! RFC 6238 TOTP code generation.
//!
//! Accepts either an `otpauth://totp/…` URL (which carries algorithm, digits,
//! step) or a bare base32-encoded secret with sensible defaults
//! (SHA-1, 6 digits, 30 s step).
//!
//! Secret-length validation is intentionally *not* enforced: ks consumes secrets
//! issued by arbitrary services, many of which use 80- or 96-bit secrets, so we
//! accept whatever the provider gave (matching `oathtool`, `pass-otp` and the
//! common authenticator apps) instead of rejecting valid real-world codes.

use totp_rs::{Algorithm, Secret as TotpSecret, TOTP};

use crate::error::{Error, Result};

/// The result of generating a TOTP code.
#[derive(Debug, Clone)]
pub struct Code {
    /// The current numeric code (zero-padded).
    pub value: String,
    /// Seconds until the code rotates.
    pub remaining_secs: u64,
}

/// Builds a [`TOTP`] from the stored secret material.
fn from_value(value: &str) -> Result<TOTP> {
    let trimmed = value.trim();
    if trimmed.starts_with("otpauth://") {
        // `*_unchecked` skips totp-rs's 128-bit minimum-length assertion, which is
        // a *provisioning* recommendation, not a rule for consuming existing
        // secrets; enforcing it would reject ubiquitous 80-bit service secrets.
        TOTP::from_url_unchecked(trimmed).map_err(|e| Error::InvalidTotp(e.to_string()))
    } else {
        let bytes = TotpSecret::Encoded(trimmed.to_owned())
            .to_bytes()
            .map_err(|e| Error::InvalidTotp(format!("base32 secret: {e}")))?;
        Ok(TOTP::new_unchecked(
            Algorithm::SHA1,
            6,
            1,
            30,
            bytes,
            None,
            "ks".to_owned(),
        ))
    }
}

/// Generates the current TOTP [`Code`] for the given secret value.
///
/// # Errors
/// Returns [`Error::InvalidTotp`] if the value cannot be parsed or the system
/// clock cannot be queried.
pub fn current(value: &str) -> Result<Code> {
    let totp = from_value(value)?;
    let code = totp
        .generate_current()
        .map_err(|e| Error::InvalidTotp(e.to_string()))?;
    let remaining = totp.ttl().map_err(|e| Error::InvalidTotp(e.to_string()))?;
    Ok(Code {
        value: code,
        remaining_secs: remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_from_base32_secret() {
        let code = current("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").expect("generate");
        assert_eq!(code.value.len(), 6);
        assert!(code.value.chars().all(|c| c.is_ascii_digit()));
        assert!(code.remaining_secs <= 30);
    }

    #[test]
    fn accepts_real_world_short_secret() {
        // 16 base32 chars = 80 bits: below the RFC's provisioning minimum but
        // ubiquitous in the wild (e.g. Google's sample key). ks must read it.
        let code = current("JBSWY3DPEHPK3PXP").expect("80-bit secret must work");
        assert_eq!(code.value.len(), 6);
    }

    #[test]
    fn accepts_short_secret_via_otpauth_url() {
        let code = current("otpauth://totp/Demo:alice?secret=JBSWY3DPEHPK3PXP&issuer=Demo")
            .expect("80-bit url secret must work");
        assert_eq!(code.value.len(), 6);
    }

    #[test]
    fn rejects_garbage() {
        assert!(current("not a secret!@#").is_err());
    }
}
