//! SafeReturn core — the backup engine library (no UI, no Windows-only
//! code). Everything a shell can ask the engine to do is built on this.
//!
//! Modules:
//! - `plain` — the original S1 prototype store (unencrypted), kept as the
//!   reference implementation its tests were written against.
//! - `crypto` — volume keys: Argon2id passphrase derivation, XChaCha20-
//!   Poly1305 key wraps, the recovery-key file format.
//! - `volume` — the encrypted, self-describing backup volume: header,
//!   content-addressed chunk records (compress → encrypt → store).
//! - `sets` — backup sets and their manifests, Level-1 verify, restore,
//!   and the manifest-rebuildable catalog.
//! - `engine` — the shell-contract-facing API: contract events, restore
//!   plans with single-use plan tokens, Level-2 File Rehearsal.
//! - `error` — named errors with stable machine codes and fix paths.

pub mod crypto;
pub mod engine;
pub mod error;
pub mod hex;
pub mod plain;
pub mod sets;
pub mod volume;

pub use error::{ChunkCorruptReason, CoreError, Result};

// Prototype surface, re-exported at the crate root exactly as before.
pub use plain::{ChunkStore, FileEntry, Manifest, VerifyReport, CHUNK_SIZE};

// Production store surface.
pub use crypto::{KdfParams, VolumeKey, WrappedKey};
pub use engine::{
    format_bytes, now_unix, select_rehearsal_files, Engine, FileRehearsalEntry, FileRehearsalReport,
};
pub use sets::{
    backup_tree, list_set_ids, list_sets, plan_target_states, read_catalog, read_set_manifest,
    rebuild_catalog, restore_file, restore_files, restore_set, summarize, verify_set,
    BackupOutcome, Catalog, CatalogSet, ChunkFailure, RestoreOutcome, SetFileEntry, SetManifest,
    SetVerifyReport, SkippedEntry, TargetState, SET_CHUNK_SIZE, SET_FORMAT_VERSION,
};
pub use volume::{sha256_hex, UnlockedVolume, Volume, VolumeHeader, VOLUME_FORMAT_VERSION};
