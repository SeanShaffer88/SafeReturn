//! Key management for a backup volume.
//!
//! One random 256-bit **volume key** encrypts every chunk. The volume key
//! itself is stored twice in the volume header, wrapped (encrypted) two
//! independent ways, so either credential opens the volume:
//!
//! 1. **Passphrase** — Argon2id (parameters stored in the header) derives
//!    a wrapping key from the user's passphrase and a random salt.
//! 2. **Recovery key** — a random 256-bit key the user saves as a file at
//!    volume-creation time. It is already full-entropy, so it is used
//!    directly as the second wrapping key (no KDF needed).
//!
//! Wrapping uses XChaCha20-Poly1305 with a fresh random 192-bit nonce per
//! wrap and a domain-separation AAD. The same AEAD protects chunks (see
//! `volume.rs`): XChaCha20's large nonce makes random nonces safe (nonce
//! reuse across distinct plaintexts under one key is the failure mode of
//! 96-bit-nonce constructions; with 192-bit random nonces the collision
//! probability is negligible, and a chunk is only ever stored once thanks
//! to content addressing, so a nonce is never reused for the same data).
//!
//! No home-rolled primitives: Argon2id and XChaCha20-Poly1305 come from
//! the RustCrypto crates; randomness from the OS via `getrandom`.

use crate::error::{CoreError, Result};
use crate::hex;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const SALT_LEN: usize = 16;

/// AAD binding wrapped keys to this exact purpose, so a wrapped-key blob
/// can never be mistaken for (or replayed as) chunk ciphertext.
const WRAP_AAD: &[u8] = b"safereturn/volume-key-wrap/v1";

/// Argon2id parameters, stored in the volume header so they can be raised
/// later without breaking existing volumes. Defaults: 32 MiB, 3 passes —
/// roughly a few hundred ms on a desktop, paid once per unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub lanes: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 32 * 1024,
            iterations: 3,
            lanes: 1,
        }
    }
}

/// The volume key. Zeroized on drop; never serialized, never logged.
pub struct VolumeKey(Zeroizing<[u8; KEY_LEN]>);

impl VolumeKey {
    pub fn generate() -> Result<Self> {
        Ok(Self(Zeroizing::new(random_array::<KEY_LEN>()?)))
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A volume key encrypted under some wrapping key. Stored in volume.json.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Algorithm id, so the wrap can evolve: 1 = XChaCha20-Poly1305.
    pub alg: u32,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| CoreError::Io {
        path: None,
        source: std::io::Error::other(format!("OS randomness unavailable: {e}")),
    })?;
    Ok(buf)
}

pub fn random_vec(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| CoreError::Io {
        path: None,
        source: std::io::Error::other(format!("OS randomness unavailable: {e}")),
    })?;
    Ok(buf)
}

/// Derive the passphrase wrapping key with Argon2id.
pub fn derive_key_from_passphrase(
    passphrase: &str,
    salt: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.lanes,
        Some(KEY_LEN),
    )
    .map_err(|e| CoreError::Io {
        path: None,
        source: std::io::Error::other(format!("invalid Argon2id parameters: {e}")),
    })?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut *out)
        .map_err(|e| CoreError::Io {
            path: None,
            source: std::io::Error::other(format!("Argon2id failed: {e}")),
        })?;
    Ok(out)
}

/// AEAD-encrypt `plaintext` under `key` with a fresh random nonce.
/// Returns (nonce, ciphertext). Used for key wraps and chunks alike.
pub fn seal(key: &[u8; KEY_LEN], aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = random_vec(NONCE_LEN)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CoreError::Io {
            path: None,
            source: std::io::Error::other("encryption failed"),
        })?;
    Ok((nonce, ciphertext))
}

/// Reverse of `seal`. AEAD failure is returned as-is (Err(())), because
/// each caller maps it to a different named error (UnlockFailed for key
/// wraps, ChunkCorrupt for chunks).
pub fn open(
    key: &[u8; KEY_LEN],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> std::result::Result<Zeroizing<Vec<u8>>, ()> {
    if nonce.len() != NONCE_LEN {
        return Err(());
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| ())
}

pub fn wrap_volume_key(wrapping_key: &[u8; KEY_LEN], volume_key: &VolumeKey) -> Result<WrappedKey> {
    let (nonce, ciphertext) = seal(wrapping_key, WRAP_AAD, volume_key.as_bytes())?;
    Ok(WrappedKey {
        alg: 1,
        nonce_hex: hex::encode(&nonce),
        ciphertext_hex: hex::encode(&ciphertext),
    })
}

pub fn unwrap_volume_key(wrapping_key: &[u8; KEY_LEN], wrapped: &WrappedKey) -> Result<VolumeKey> {
    if wrapped.alg != 1 {
        return Err(CoreError::UnlockFailed);
    }
    let nonce = hex::decode(&wrapped.nonce_hex).ok_or(CoreError::UnlockFailed)?;
    let ciphertext = hex::decode(&wrapped.ciphertext_hex).ok_or(CoreError::UnlockFailed)?;
    let plain =
        open(wrapping_key, WRAP_AAD, &nonce, &ciphertext).map_err(|_| CoreError::UnlockFailed)?;
    if plain.len() != KEY_LEN {
        return Err(CoreError::UnlockFailed);
    }
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(&plain);
    Ok(VolumeKey::from_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Recovery key file
//
// Text format (user saves this file somewhere safe, e.g. a USB stick or a
// printed page):
//
//   SAFERETURN RECOVERY KEY
//   volume: <volume-id-hex>
//   key: <64 hex chars, grouped in 8s for readability>
//   check: <first 8 hex chars of SHA-256(key)>
//
// The check line lets us reject a mistyped/damaged key file as
// BadRecoveryKey ("the file is damaged") instead of the misleading
// UnlockFailed ("wrong key") — and a *well-formed* key that belongs to a
// different volume still fails as UnlockFailed, as it should.

pub const RECOVERY_KEY_HEADER: &str = "SAFERETURN RECOVERY KEY";

pub fn format_recovery_key(volume_id: &str, key: &[u8; KEY_LEN]) -> String {
    let hexkey = hex::encode(key);
    let grouped: Vec<String> = hexkey
        .as_bytes()
        .chunks(8)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    format!(
        "{RECOVERY_KEY_HEADER}\nvolume: {volume_id}\nkey: {}\ncheck: {}\n",
        grouped.join(" "),
        recovery_key_check(key)
    )
}

pub fn recovery_key_check(key: &[u8; KEY_LEN]) -> String {
    let digest = Sha256::digest(key);
    hex::encode(&digest[..4])
}

pub fn parse_recovery_key(text: &str) -> Result<[u8; KEY_LEN]> {
    let bad = |reason: &str| CoreError::BadRecoveryKey {
        reason: reason.to_string(),
    };
    let mut key_hex: Option<String> = None;
    let mut check: Option<String> = None;
    let mut saw_header = false;
    for line in text.lines() {
        let line = line.trim();
        if line == RECOVERY_KEY_HEADER {
            saw_header = true;
        } else if let Some(v) = line.strip_prefix("key:") {
            key_hex = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("check:") {
            check = Some(v.trim().to_string());
        }
    }
    if !saw_header {
        return Err(bad("missing the 'SAFERETURN RECOVERY KEY' heading"));
    }
    let key_hex = key_hex.ok_or_else(|| bad("missing the 'key:' line"))?;
    let bytes = hex::decode(&key_hex).ok_or_else(|| bad("the key line is not valid hex"))?;
    if bytes.len() != KEY_LEN {
        return Err(bad(
            "the key is the wrong length (expected 64 hex characters)",
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    if let Some(check) = check {
        if !check.eq_ignore_ascii_case(&recovery_key_check(&key)) {
            key.zeroize();
            return Err(bad(
                "the check code does not match the key — a character was probably mistyped or the file was damaged",
            ));
        }
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_roundtrip_and_wrong_key() {
        let volume_key = VolumeKey::from_bytes([7u8; KEY_LEN]);
        let wrapping = [9u8; KEY_LEN];
        let wrapped = wrap_volume_key(&wrapping, &volume_key).unwrap();
        let back = unwrap_volume_key(&wrapping, &wrapped).unwrap();
        assert_eq!(back.as_bytes(), volume_key.as_bytes());
        let wrong = [8u8; KEY_LEN];
        assert!(matches!(
            unwrap_volume_key(&wrong, &wrapped),
            Err(CoreError::UnlockFailed)
        ));
    }

    #[test]
    fn passphrase_derivation_is_deterministic_and_sensitive() {
        let salt = [3u8; SALT_LEN];
        let params = KdfParams {
            memory_kib: 1024,
            iterations: 1,
            lanes: 1,
        };
        let a = derive_key_from_passphrase("correct horse", &salt, &params).unwrap();
        let b = derive_key_from_passphrase("correct horse", &salt, &params).unwrap();
        let c = derive_key_from_passphrase("correct Horse", &salt, &params).unwrap();
        assert_eq!(*a, *b);
        assert_ne!(*a, *c);
    }

    #[test]
    fn recovery_key_file_roundtrip_and_typo_detection() {
        let key = [42u8; KEY_LEN];
        let text = format_recovery_key("abcd1234", &key);
        assert_eq!(parse_recovery_key(&text).unwrap(), key);
        // A single mistyped hex character must trip the check code.
        let typo = text.replacen("2a2a", "2b2a", 1);
        assert!(matches!(
            parse_recovery_key(&typo),
            Err(CoreError::BadRecoveryKey { .. })
        ));
        assert!(matches!(
            parse_recovery_key("just some text"),
            Err(CoreError::BadRecoveryKey { .. })
        ));
    }
}
