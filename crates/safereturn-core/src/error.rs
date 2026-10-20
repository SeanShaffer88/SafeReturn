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
    /// System facts failed validation: an unknown without a reason, a
    /// fact without a source, an ambiguous BCD capture, or an
    /// unsupported facts format version (S3 honesty schema).
    InvalidSystemFacts {
        reason: String,
    },
    /// A set already carries a system-facts section; recorded facts
    /// are never silently replaced.
    SystemFactsAlreadyPresent {
        set_id: String,
    },
    /// Plan token is unknown, already used, or not a token at all.
    InvalidPlanToken,
    /// The target changed after the restore plan was made; the plan no
    /// longer describes reality, so executing it would be a surprise.
    PlanStale {
        detail: String,
    },
    /// Media target is under the builder's minimum size (S4).
    MediaTargetTooSmall {
        size_bytes: u64,
        min_bytes: u64,
    },
    /// The WinPE image + payload cannot fit the FAT32 boot partition
    /// ceiling, or the target has no room left for a usable data
    /// partition after the boot partition is laid out (S4).
    MediaPayloadTooLarge {
        needed_bytes: u64,
        available_bytes: u64,
    },
    /// Media target is not removable and the caller did not explicitly
    /// override. Erasing a fixed disk by accident is the failure this
    /// refusal exists to prevent (S4).
    MediaTargetNotRemovable,
    /// The WinPE source (winpe.wim) the caller named is not there (S4).
    MediaSourceMissing {
        detail: String,
    },
    /// Media facts failed validation (serial suffix, payload paths,
    /// driver list) — planning refuses rather than guessing (S4).
    MediaInvalidFacts {
        reason: String,
    },
    /// Media plan token is unknown, already used, or not a token.
    MediaInvalidPlanToken,
    /// The target device changed after the media plan was made (size,
    /// removable flag, or serial suffix differ at execute time), so
    /// executing would erase a device other than the one confirmed.
    MediaPlanStale {
        detail: String,
    },
    /// The directory given for media verification carries no
    /// safereturn-media.json — it is not SafeReturn media (or the
    /// wrong partition was picked).
    MediaManifestMissing {
        path: PathBuf,
    },
    /// The media manifest or boot-test marker exists but is not valid
    /// data of the expected schema/version. Reported as invalid data,
    /// never treated as a passing check.
    MediaManifestInvalid {
        reason: String,
    },
    /// A feature exists only on Windows and this build is running
    /// somewhere else (media execution, snapshot capture). The typed
    /// error is the contract: callers render it, never a panic.
    UnsupportedPlatform {
        feature: &'static str,
    },
    /// On Windows, a live operation (media build, snapshot) was asked
    /// for but the explicit live-enable environment switch is not set.
    /// Real hardware operations never start from an ambient call.
    LiveNotEnabled {
        env_var: &'static str,
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
            CoreError::InvalidSystemFacts { .. } => "backup.invalid_system_facts",
            CoreError::SystemFactsAlreadyPresent { .. } => "set.system_facts_already_present",
            CoreError::InvalidPlanToken => "restore.invalid_plan_token",
            CoreError::PlanStale { .. } => "restore.plan_stale",
            CoreError::MediaTargetTooSmall { .. } => "media.target_too_small",
            CoreError::MediaPayloadTooLarge { .. } => "media.payload_too_large",
            CoreError::MediaTargetNotRemovable => "media.target_not_removable",
            CoreError::MediaSourceMissing { .. } => "media.winpe_source_missing",
            CoreError::MediaInvalidFacts { .. } => "media.invalid_facts",
            CoreError::MediaInvalidPlanToken => "media.invalid_plan_token",
            CoreError::MediaPlanStale { .. } => "media.plan_stale",
            CoreError::MediaManifestMissing { .. } => "media.manifest_missing",
            CoreError::MediaManifestInvalid { .. } => "media.manifest_invalid",
            CoreError::UnsupportedPlatform { .. } => "core.unsupported_platform",
            CoreError::LiveNotEnabled { .. } => "media.live_not_enabled",
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
            CoreError::InvalidSystemFacts { reason } => write!(
                f,
                "the system facts are not usable: {reason}. Facts must name a source for every value, and a reason for every value that could not be determined. Nothing was attached to the backup set."
            ),
            CoreError::SystemFactsAlreadyPresent { set_id } => write!(
                f,
                "backup set {set_id} already has system facts recorded, and recorded facts are never replaced silently. The existing facts were left exactly as they were."
            ),
            CoreError::InvalidPlanToken => write!(
                f,
                "that restore plan is not valid (unknown or already used). Make a new restore plan and confirm it before restoring."
            ),
            CoreError::PlanStale { detail } => write!(
                f,
                "the files on the target changed after this restore plan was made ({detail}), so the plan no longer matches reality. Nothing was written. Make a new plan to see the current state."
            ),
            CoreError::MediaTargetTooSmall {
                size_bytes,
                min_bytes,
            } => write!(
                f,
                "this device is too small for recovery media: it has {size_bytes} bytes, and SafeReturn needs at least {min_bytes} bytes (8 GiB) to lay out a WinPE boot partition plus a data partition. Nothing was written to the device. Use a larger USB stick."
            ),
            CoreError::MediaPayloadTooLarge {
                needed_bytes,
                available_bytes,
            } => write!(
                f,
                "the WinPE image and recovery app do not fit: the layout needs {needed_bytes} bytes but only {available_bytes} bytes are available. Nothing was written to the device. Use a larger device, or remove payload files/drivers and plan again."
            ),
            CoreError::MediaTargetNotRemovable => write!(
                f,
                "this device is not removable media, so SafeReturn will not erase it for recovery media unless the override is set explicitly. Nothing was written. Pick a USB stick, or set the non-removable override if this really is the device to erase."
            ),
            CoreError::MediaSourceMissing { detail } => write!(
                f,
                "the WinPE source is missing: {detail}. Nothing was written to the device."
            ),
            CoreError::MediaInvalidFacts { reason } => write!(
                f,
                "the media facts are not usable: {reason}. Nothing was written to the device. Fix the facts and plan again."
            ),
            CoreError::MediaInvalidPlanToken => write!(
                f,
                "that media plan is not valid (unknown or already used). Nothing was written to the device. Make a new media plan and confirm it before creating media."
            ),
            CoreError::MediaPlanStale { detail } => write!(
                f,
                "the target device changed after this media plan was made ({detail}), so the plan no longer describes the device that would be erased. Nothing was written. Make a new media plan for the device as it is now."
            ),
            CoreError::MediaManifestMissing { path } => write!(
                f,
                "{} does not look like SafeReturn recovery media (no safereturn-media.json). If you pointed at a partition of the media, try the other partition — the manifest lives on the boot (FAT32) partition.",
                path.display()
            ),
            CoreError::MediaManifestInvalid { reason } => write!(
                f,
                "the SafeReturn media data is not valid: {reason}. It is reported as invalid, not as a pass. Rebuild the media, or restore safereturn-media.json from a known-good copy."
            ),
            CoreError::UnsupportedPlatform { feature } => write!(
                f,
                "{feature} only works on Windows — this machine is running something else, so it cannot be done here. Nothing was changed."
            ),
            CoreError::LiveNotEnabled { env_var } => write!(
                f,
                "live media creation is a real hardware operation and is not enabled: set the {env_var}=1 environment variable to permit it. Nothing was written to any device."
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
