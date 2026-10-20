//! The backup volume: an on-disk directory that is fully self-describing.
//!
//! Layout:
//! ```text
//! <volume>/
//!   volume.json            header: format version, volume id, Argon2id
//!                          salt/params, volume key wrapped by passphrase
//!                          and by recovery key
//!   chunks/<2 hex>/<id>    chunk records (content-addressed by the
//!                          SHA-256 of the *plaintext* chunk)
//!   sets/<set_id>.json     one manifest per backup set (source of truth)
//!   catalog.json           rebuildable index over the set manifests
//! ```
//! If every SafeReturn install vanished, the recovery environment needs
//! only this directory: header + manifests describe everything, and
//! `sets::rebuild_catalog` regenerates the index from manifests alone.
//!
//! Chunk record format (binary, all integers little-endian):
//! ```text
//!   0  magic "SRC1" (4)
//!   4  record format version u8 = 1
//!   5  compression alg u8   (0 = none, 1 = zstd [reserved], 2 = deflate)
//!   6  encryption alg u8    (1 = XChaCha20-Poly1305)
//!   7  reserved u8 = 0
//!   8  nonce (24 bytes, random per stored chunk)
//!  32  plaintext length u64
//!  40  ciphertext: AEAD(compressed plaintext), AAD = chunk id bytes
//! ```
//! Storing the algorithm ids in every record means the format can evolve
//! (e.g. zstd replacing deflate) without a volume-level migration: old
//! chunks stay readable, new chunks use the new id.
//!
//! Compression is DEFLATE (flate2/miniz_oxide, pure Rust). zstd remains
//! alg id 1, reserved: the zstd crate's C build breaks this repo's
//! mandated Windows-target check from non-Windows hosts (see Cargo.toml).

use crate::crypto::{
    derive_key_from_passphrase, random_array, unwrap_volume_key, wrap_volume_key, KdfParams,
    VolumeKey, WrappedKey, KEY_LEN, NONCE_LEN, SALT_LEN,
};
use crate::error::{io_at, ChunkCorruptReason, CoreError, Result};
use crate::hex;
use flate2::{read::DeflateDecoder, write::DeflateEncoder, Compression};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const VOLUME_FORMAT_VERSION: u32 = 1;
const CHUNK_MAGIC: &[u8; 4] = b"SRC1";
const CHUNK_RECORD_VERSION: u8 = 1;
const COMPRESSION_NONE: u8 = 0;
const COMPRESSION_ZSTD_RESERVED: u8 = 1;
const COMPRESSION_DEFLATE: u8 = 2;
const ENCRYPTION_XCHACHA20_POLY1305: u8 = 1;

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(&Sha256::digest(data))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfSection {
    /// "argon2id"
    pub alg: String,
    pub salt_hex: String,
    #[serde(flatten)]
    pub params: KdfParams,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeHeader {
    pub format_version: u32,
    pub volume_id: String,
    pub created_unix: u64,
    pub kdf: KdfSection,
    pub key_by_passphrase: WrappedKey,
    pub key_by_recovery: WrappedKey,
}

/// A volume directory, locked. Holds no key material.
pub struct Volume {
    root: PathBuf,
    header: VolumeHeader,
}

/// A volume directory, unlocked: header plus the volume key in memory.
pub struct UnlockedVolume {
    root: PathBuf,
    header: VolumeHeader,
    key: VolumeKey,
}

fn volume_json_path(root: &Path) -> PathBuf {
    root.join("volume.json")
}

impl Volume {
    /// Create a new volume. Refuses if `root` already holds a volume.
    /// Returns the volume and the recovery key (the caller decides where
    /// the user saves it — see `crypto::format_recovery_key`).
    pub fn create(
        root: impl AsRef<Path>,
        passphrase: &str,
        created_unix: u64,
    ) -> Result<(Volume, [u8; KEY_LEN])> {
        let root = root.as_ref().to_path_buf();
        if volume_json_path(&root).exists() {
            return Err(CoreError::VolumeAlreadyExists { path: root });
        }
        fs::create_dir_all(root.join("chunks")).map_err(|e| io_at(&root, e))?;
        fs::create_dir_all(root.join("sets")).map_err(|e| io_at(&root, e))?;

        let volume_key = VolumeKey::generate()?;
        let recovery_key = random_array::<KEY_LEN>()?;
        let salt = random_array::<SALT_LEN>()?;
        let params = KdfParams::default();
        let passphrase_wrapping = derive_key_from_passphrase(passphrase, &salt, &params)?;
        let header = VolumeHeader {
            format_version: VOLUME_FORMAT_VERSION,
            volume_id: hex::encode(&random_array::<16>()?),
            created_unix,
            kdf: KdfSection {
                alg: "argon2id".to_string(),
                salt_hex: hex::encode(&salt),
                params,
            },
            key_by_passphrase: wrap_volume_key(&passphrase_wrapping, &volume_key)?,
            key_by_recovery: wrap_volume_key(&recovery_key, &volume_key)?,
        };
        let json = serde_json::to_string_pretty(&header).unwrap();
        fs::write(volume_json_path(&root), json).map_err(|e| io_at(&root, e))?;
        Ok((Volume { root, header }, recovery_key))
    }

    /// Open an existing volume (still locked).
    pub fn open(root: impl AsRef<Path>) -> Result<Volume> {
        let root = root.as_ref().to_path_buf();
        let path = volume_json_path(&root);
        if !path.exists() {
            return Err(CoreError::NotAVolume { path: root });
        }
        let text = fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
        let header: VolumeHeader =
            serde_json::from_str(&text).map_err(|source| CoreError::Json {
                path: path.clone(),
                source,
            })?;
        if header.format_version != VOLUME_FORMAT_VERSION {
            return Err(CoreError::Json {
                path,
                source: serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "volume format {} is newer than this SafeReturn understands ({})",
                        header.format_version, VOLUME_FORMAT_VERSION
                    ),
                )),
            });
        }
        Ok(Volume { root, header })
    }

    pub fn header(&self) -> &VolumeHeader {
        &self.header
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn unlock_with_passphrase(&self, passphrase: &str) -> Result<UnlockedVolume> {
        let salt = hex::decode(&self.header.kdf.salt_hex).ok_or(CoreError::UnlockFailed)?;
        let wrapping = derive_key_from_passphrase(passphrase, &salt, &self.header.kdf.params)?;
        let key = unwrap_volume_key(&wrapping, &self.header.key_by_passphrase)?;
        Ok(UnlockedVolume {
            root: self.root.clone(),
            header: self.header.clone(),
            key,
        })
    }

    pub fn unlock_with_recovery_key(&self, recovery_key: &[u8; KEY_LEN]) -> Result<UnlockedVolume> {
        let key = unwrap_volume_key(recovery_key, &self.header.key_by_recovery)?;
        Ok(UnlockedVolume {
            root: self.root.clone(),
            header: self.header.clone(),
            key,
        })
    }
}

impl UnlockedVolume {
    pub fn volume_id(&self) -> &str {
        &self.header.volume_id
    }

    pub fn header(&self) -> &VolumeHeader {
        &self.header
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn chunk_path(&self, chunk_id: &str) -> PathBuf {
        self.root.join("chunks").join(&chunk_id[..2]).join(chunk_id)
    }

    /// Compress + encrypt + store one plaintext chunk. Content-addressed:
    /// storing the same plaintext again is a no-op (dedupe), which is also
    /// what guarantees a chunk's random nonce is never reused for the same
    /// data. Returns the chunk id (SHA-256 of the plaintext).
    pub fn put_chunk(&self, plaintext: &[u8]) -> Result<String> {
        let chunk_id = sha256_hex(plaintext);
        let path = self.chunk_path(&chunk_id);
        if path.exists() {
            return Ok(chunk_id);
        }
        let record = self.encode_chunk(&chunk_id, plaintext)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| io_at(&path, e))?;
        }
        // Write to a temp file in the same directory, then rename: a crash
        // mid-write leaves a stray temp file, never a torn chunk record
        // masquerading under a valid chunk id.
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, &record).map_err(|e| io_at(&tmp, e))?;
        fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
        Ok(chunk_id)
    }

    fn encode_chunk(&self, chunk_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(plaintext).map_err(|e| CoreError::Io {
            path: None,
            source: e,
        })?;
        let compressed = encoder.finish().map_err(|e| CoreError::Io {
            path: None,
            source: e,
        })?;
        let (body, compression_alg) = if compressed.len() < plaintext.len() {
            (compressed, COMPRESSION_DEFLATE)
        } else {
            (plaintext.to_vec(), COMPRESSION_NONE)
        };
        let (nonce, ciphertext) =
            crate::crypto::seal(self.key.as_bytes(), chunk_id.as_bytes(), &body)?;
        let mut record = Vec::with_capacity(40 + ciphertext.len());
        record.extend_from_slice(CHUNK_MAGIC);
        record.push(CHUNK_RECORD_VERSION);
        record.push(compression_alg);
        record.push(ENCRYPTION_XCHACHA20_POLY1305);
        record.push(0);
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&(plaintext.len() as u64).to_le_bytes());
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// Read, decrypt, decompress, and *re-hash* one chunk. A chunk is only
    /// handed out if its plaintext hashes to the id it was asked for —
    /// AEAD alone would not catch two valid records being swapped.
    pub fn get_chunk(&self, chunk_id: &str) -> Result<Vec<u8>> {
        let path = self.chunk_path(chunk_id);
        let record = match fs::read(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(CoreError::ChunkMissing {
                    chunk_id: chunk_id.to_string(),
                })
            }
            Err(e) => return Err(io_at(&path, e)),
        };
        let corrupt = |reason: ChunkCorruptReason| CoreError::ChunkCorrupt {
            chunk_id: chunk_id.to_string(),
            reason,
        };
        // Smallest valid record: 40-byte header + 16-byte AEAD tag.
        if record.len() < 40 + 16
            || &record[0..4] != CHUNK_MAGIC
            || record[4] != CHUNK_RECORD_VERSION
            || record[6] != ENCRYPTION_XCHACHA20_POLY1305
        {
            return Err(corrupt(ChunkCorruptReason::BadRecord));
        }
        let compression_alg = record[5];
        let nonce = &record[8..8 + NONCE_LEN];
        let plaintext_len = u64::from_le_bytes(record[32..40].try_into().unwrap()) as usize;
        let ciphertext = &record[40..];
        let body = crate::crypto::open(self.key.as_bytes(), chunk_id.as_bytes(), nonce, ciphertext)
            .map_err(|_| corrupt(ChunkCorruptReason::DecryptFailed))?;
        let plaintext = match compression_alg {
            COMPRESSION_NONE => body.to_vec(),
            COMPRESSION_DEFLATE => {
                let mut out = Vec::with_capacity(plaintext_len);
                DeflateDecoder::new(&body[..])
                    .read_to_end(&mut out)
                    .map_err(|_| corrupt(ChunkCorruptReason::DecompressFailed))?;
                out
            }
            COMPRESSION_ZSTD_RESERVED => {
                return Err(corrupt(ChunkCorruptReason::BadRecord));
            }
            _ => return Err(corrupt(ChunkCorruptReason::BadRecord)),
        };
        if plaintext.len() != plaintext_len || sha256_hex(&plaintext) != chunk_id {
            return Err(corrupt(ChunkCorruptReason::HashMismatch));
        }
        Ok(plaintext)
    }

    pub fn chunk_exists(&self, chunk_id: &str) -> bool {
        self.chunk_path(chunk_id).exists()
    }

    /// All chunk ids physically present on the volume, sorted. Used by
    /// diagnostics and by tests proving dedupe.
    pub fn chunk_ids_on_disk(&self) -> Result<Vec<String>> {
        let chunks_dir = self.root.join("chunks");
        let mut ids = Vec::new();
        if chunks_dir.exists() {
            for fan in fs::read_dir(&chunks_dir).map_err(|e| io_at(&chunks_dir, e))? {
                let fan = fan.map_err(|e| io_at(&chunks_dir, e))?;
                if fan.path().is_dir() {
                    for entry in fs::read_dir(fan.path()).map_err(|e| io_at(&fan.path(), e))? {
                        let entry = entry.map_err(|e| io_at(&fan.path(), e))?;
                        if entry.path().extension().is_some_and(|x| x == "tmp") {
                            continue;
                        }
                        ids.push(entry.file_name().to_string_lossy().into_owned());
                    }
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub(crate) fn sets_dir(&self) -> PathBuf {
        self.root.join("sets")
    }

    pub(crate) fn catalog_path(&self) -> PathBuf {
        self.root.join("catalog.json")
    }
}
