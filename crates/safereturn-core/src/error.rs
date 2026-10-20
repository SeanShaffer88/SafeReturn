//! Named, honest errors for the engine core.
//!
//! Every failure a user or shell can hit has a distinct variant, a stable
//! machine `code()` (the shell contract's EngineError.code), and a Display
//! message that says what happened and the fix path. Nothing in the core
//! fails with a bare "error" string, and authentication failures are
//! deliberately indistinguishable (wrong passphrase vs. damaged key
//! material must not be an oracle).

use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkCorruptReason {
    /// AEAD tag check failed — the bytes were altered (or the key is wrong,
    /// but a wrong key is caught earlier, at volume unlock).
    DecryptFailed,
    /// Decrypted plaintext does not hash to the chunk id it was stored
    /// under (e.g. two chunks' records were swapped).
    HashMismatch,
    /// Plaintext could not be decompressed after successful decryption.
    DecompressFailed,
    /// The on-disk record is structurally invalid (bad magic/version/ids).
    BadRecord,
}

impl ChunkCorruptReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            ChunkCorruptReason::DecryptFailed => "decrypt_failed",
            ChunkCorruptReason::HashMismatch => "hash_mismatch",
            ChunkCorruptReason::DecompressFailed => "decompress_failed",
            ChunkCorruptReason::BadRecord => "bad_record",
        }
    }
}

impl fmt::Display for ChunkCorruptReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum CoreError {
    Io {
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// The directory does not contain a SafeReturn volume header.
    NotAVolume {
        path: PathBuf,
    },
    /// Refusing to initialize over an existing volume.
    VolumeAlreadyExists {
        path: PathBuf,
    },
    /// Passphrase or recovery key did not unlock the volume. One variant
    /// for wrong passphrase, wrong recovery key, and damaged wrapped-key
    /// material on purpose — see module docs.
    UnlockFailed,
    /// The recovery key file itself is malformed (not merely wrong).
    BadRecoveryKey {
        reason: String,
    },
    ChunkMissing {
        chunk_id: String,
    },
    ChunkCorrupt {
        chunk_id: String,
        reason: ChunkCorruptReason,
    },
    SetNotFound {
        set_id: String,
    },
    SetAlreadyExists {
        set_id: String,
    },
    FileNotInSet {
        set_id: String,
        path: String,
    },
    /// A source file could not be read during backup. The backup aborts;
    /// no set manifest is written, so no partial set ever appears.
    SourceUnreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Two source roots map to the same display name inside a set.
    RootNameCollision {
        name: String,
    },
    /// A capture root does not lie on the volume a mapped capture
    /// source serves (or would escape it via ".."): it cannot be read
    /// from that volume's snapshot.
    CaptureRootOutsideVolume {
        root: String,
        volume: String,
    },
    /// A restore target file exists with different content and was not in
    /// the approved overwrite set.
    RestoreConflict {
        path: String,
    },
    /// Plan token is unknown, already used, or not a token at all.
    InvalidPlanToken,
    /// The target changed after the restore plan was made; the plan no
    /// longer describes reality, so executing it would be a surprise.
    PlanStale {
        detail: String,
    },
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    /// Stable machine code, used as the shell contract's EngineError.code.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Io { .. } => "core.io",
            CoreError::Json { .. } => "core.damaged_data",
            CoreError::NotAVolume { .. } => "volume.not_a_volume",
            CoreError::VolumeAlreadyExists { .. } => "volume.already_exists",
            CoreError::UnlockFailed => "volume.unlock_failed",
            CoreError::BadRecoveryKey { .. } => "volume.bad_recovery_key",
            CoreError::ChunkMissing { .. } => "chunk.missing",
            CoreError::ChunkCorrupt { .. } => "chunk.corrupt",
            CoreError::SetNotFound { .. } => "set.not_found",
            CoreError::SetAlreadyExists { .. } => "set.already_exists",
            CoreError::FileNotInSet { .. } => "set.file_not_found",
            CoreError::SourceUnreadable { .. } => "backup.source_unreadable",
            CoreError::RootNameCollision { .. } => "backup.root_name_collision",
            CoreError::CaptureRootOutsideVolume { .. } => "backup.capture_root_outside_volume",
            CoreError::RestoreConflict { .. } => "restore.conflict",
            CoreError::InvalidPlanToken => "restore.invalid_plan_token",
            CoreError::PlanStale { .. } => "restore.plan_stale",
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Io { path, source } => match path {
                Some(p) => write!(f, "could not access {}: {source}", p.display()),
                None => write!(f, "input/output error: {source}"),
            },
            CoreError::Json { path, source } => write!(
                f,
                "{} is damaged (not valid SafeReturn data): {source}. Restore it from another copy of the backup if you have one.",
                path.display()
            ),
            CoreError::NotAVolume { path } => write!(
                f,
                "{} is not a SafeReturn backup volume (no volume.json). Pick the folder that SafeReturn created for backups.",
                path.display()
            ),
            CoreError::VolumeAlreadyExists { path } => write!(
                f,
                "{} is already a SafeReturn backup volume. To start over, delete or rename that folder yourself first — SafeReturn will not overwrite an existing volume.",
                path.display()
            ),
            CoreError::UnlockFailed => write!(
                f,
                "that passphrase or recovery key does not open this backup volume. Check for typos (passphrases are case-sensitive), or use the recovery key file you saved when the volume was created."
            ),
            CoreError::BadRecoveryKey { reason } => write!(
                f,
                "the recovery key file is not usable: {reason}. Re-export it from SafeReturn, or type the passphrase instead."
            ),
            CoreError::ChunkMissing { chunk_id } => write!(
                f,
                "part of the backup is missing (chunk {chunk_id} is not on the volume). The backup drive may have been interrupted while writing, or files were moved. Re-run the backup; if this repeats, the drive may be failing."
            ),
            CoreError::ChunkCorrupt { chunk_id, reason } => write!(
                f,
                "part of the backup is damaged (chunk {chunk_id}: {reason}). The stored data no longer matches what was written. Re-run the backup from the original files; if this repeats, the drive may be failing."
            ),
            CoreError::SetNotFound { set_id } => write!(
                f,
                "backup set {set_id} is not on this volume. List the sets on the volume to see what is there."
            ),
            CoreError::SetAlreadyExists { set_id } => {
                write!(f, "backup set {set_id} already exists on this volume.")
            }
            CoreError::FileNotInSet { set_id, path } => write!(
                f,
                "{path} is not in backup set {set_id}. Check the path — it must match the path stored in the set exactly."
            ),
            CoreError::SourceUnreadable { path, source } => write!(
                f,
                "could not read {} during backup: {source}. The backup was stopped and no backup set was saved. Close programs that may be using the file, then run the backup again.",
                path.display()
            ),
            CoreError::RootNameCollision { name } => write!(
                f,
                "two of the folders you picked have the same name ({name}), so their files would mix together in the backup. Rename one folder, or back them up in separate runs."
            ),
            CoreError::CaptureRootOutsideVolume { root, volume } => write!(
                f,
                "cannot capture {root} from a snapshot of {volume}: that folder is not on {volume}. No backup set was saved. Pick folders on {volume}, or run the backup without a snapshot."
            ),
            CoreError::RestoreConflict { path } => write!(
                f,
                "restore stopped before writing {path}: a different file is already there and it was not in the approved plan. Nothing was overwritten. Make a new restore plan to see the current state."
            ),
            CoreError::InvalidPlanToken => write!(
                f,
                "that restore plan is not valid (unknown or already used). Make a new restore plan and confirm it before restoring."
            ),
            CoreError::PlanStale { detail } => write!(
                f,
                "the files on the target changed after this restore plan was made ({detail}), so the plan no longer matches reality. Nothing was written. Make a new plan to see the current state."
            ),
        }
    }
}

impl std::error::Error for CoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CoreError::Io { source, .. } => Some(source),
            CoreError::Json { source, .. } => Some(source),
            CoreError::SourceUnreadable { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CoreError {
    fn from(source: std::io::Error) -> Self {
        CoreError::Io { path: None, source }
    }
}

pub fn io_at(path: &PathBuf, source: std::io::Error) -> CoreError {
    CoreError::Io {
        path: Some(path.clone()),
        source,
    }
}
