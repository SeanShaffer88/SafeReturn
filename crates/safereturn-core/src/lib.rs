//! SafeReturn core — the backup engine library. No UI. Everything a
//! shell can ask the engine to do is built on this. Platform-agnostic
//! except for one fenced-off piece: the S3 Windows system-facts
//! gatherer skeleton (`system`, cfg(windows)).
//!
//! Modules:
//! - `plain` — the original S1 prototype store (unencrypted), kept as the
//!   reference implementation its tests were written against.
//! - `crypto` — volume keys: Argon2id passphrase derivation, XChaCha20-
//!   Poly1305 key wraps, the recovery-key file format.
//! - `volume` — the encrypted, self-describing backup volume: header,
//!   content-addressed chunk records (compress → encrypt → store).
//! - `capture` — capture sources (S3): the set walk reads through a
//!   `CaptureSource` — the live filesystem by default, or a prefix-
//!   mapped snapshot root — and manifests record which one was used.
//! - `sets` — backup sets and their manifests, Level-1 verify, restore,
//!   and the manifest-rebuildable catalog.
//! - `system` — system facts for system sets (S3): boot mode, Secure
//!   Boot, BitLocker, ESP contents, WinRE, BCD capture status — each
//!   fact sourced, each unknown explicit and reasoned.
//! - `media` — recovery-media planning (S4): the pure, computed
//!   WinPE media plan (two-partition layout, ADK build steps,
//!   refusals), plus the media manifest, verification, and the
//!   boot-test marker protocol. Execution lives in `media_exec`
//!   (Windows-only) behind the engine's plan-token flow.
//! - `system_restore` — bare-metal restore planning (S5): the pure,
//!   computed whole-PC restore plan (GPT layout with sourced
//!   defaults, per-partition file application, bcdboot/reagentc
//!   post steps as data, typed refusals).
//! - `engine` — the shell-contract-facing API: contract events, restore
//!   plans with single-use plan tokens, Level-2 File Rehearsal.
//! - `error` — named errors with stable machine codes and fix paths.

pub mod capture;
pub mod crypto;
pub mod engine;
pub mod error;
pub mod hex;
pub mod media;
pub mod media_exec;
pub mod media_verify;
pub mod plain;
pub mod sets;
pub mod system;
pub mod system_restore;
pub mod system_restore_exec;
pub mod system_restore_verify;
pub mod volume;

pub use error::{ChunkCorruptReason, CoreError, Result};

// Prototype surface, re-exported at the crate root exactly as before.
pub use plain::{ChunkStore, FileEntry, Manifest, VerifyReport, CHUNK_SIZE};

// Production store surface.
pub use capture::{CaptureMode, CaptureSource, LiveSource, MappedSource};
pub use crypto::{KdfParams, VolumeKey, WrappedKey};
pub use engine::{
    format_bytes, now_unix, select_rehearsal_files, Engine, FileRehearsalEntry, FileRehearsalReport,
};
pub use media::{
    plan_media, read_media_manifest, write_media_manifest, MediaFacts, MediaLayout, MediaManifest,
    MediaPlan, MediaPlanOptions, MediaStep, MediaTargetFacts, MediaWarning, PayloadFact,
    WinPeSourceFacts, FAT32_MAX_BYTES, MEDIA_MANIFEST_FILE, MEDIA_MANIFEST_FORMAT_VERSION,
    MIN_BOOT_PARTITION_BYTES, MIN_DATA_PARTITION_BYTES, MIN_TARGET_BYTES,
    PARTITION_ALIGNMENT_BYTES, WINPE_OPTIONAL_COMPONENTS,
};
#[cfg(windows)]
pub use media_exec::WindowsAdkExecutor;
pub use media_exec::{platform_executor, MediaExecutor, UnsupportedExecutor, MEDIA_LIVE_ENV};
pub use media_verify::{
    record_boot_test, verify_media, verify_media_roots, BootFileCheck, BootTestMarker,
    BootTestStatus, MediaVerifyReport, PayloadCheck, BOOT_TEST_MARKER_FILE,
    BOOT_TEST_MARKER_FORMAT_VERSION, REQUIRED_BOOT_FILES,
};
pub use sets::{
    attach_system_facts, backup_tree, backup_tree_with_source, list_set_ids, list_sets,
    plan_target_states, read_catalog, read_set_manifest, rebuild_catalog, restore_file,
    restore_files, restore_set, summarize, verify_set, BackupOutcome, Catalog, CatalogSet,
    ChunkFailure, RestoreOutcome, SetFileEntry, SetManifest, SetVerifyReport, SkippedEntry,
    TargetState, SET_CHUNK_SIZE, SET_FORMAT_VERSION,
};
#[cfg(windows)]
pub use system::WindowsFactsGatherer;
pub use system::{
    esp_fact, list_esp_files, parse_system_facts, BcdCapture, BitLockerState, BootMode, EspFile,
    Fact, StaticFactsGatherer, SystemFacts, SystemFactsGatherer, UnavailableGatherer, WinReInfo,
    SYSTEM_FACTS_FORMAT_VERSION,
};
pub use system_restore::{
    plan_system_restore, ApplyFileStep, PartitionFilesystem, PartitionRole, PartitionSpec,
    SystemRestoreOptions, SystemRestorePlan, SystemRestorePostStep, SystemRestoreTargetFacts,
    SystemRestoreWarning, ESP_CONTENT_HEADROOM_BYTES, ESP_DEFAULT_BYTES, ESP_TYPE_GUID,
    GPT_END_RESERVE_BYTES, GPT_FRONT_RESERVE_BYTES, MSR_BYTES, REQUIRED_ESP_BOOT_FILES,
    WINDOWS_HEADROOM_MIN_BYTES, WINRE_FREE_HEADROOM_BYTES, WINRE_GPT_ATTRIBUTES,
    WINRE_IMAGE_DEST_REL, WINRE_MIN_BYTES, WINRE_TYPE_GUID,
};
#[cfg(windows)]
pub use system_restore_exec::WindowsDiskExecutor;
pub use system_restore_exec::{
    diskpart_script, platform_system_restore_executor, post_step_commands, RecordedPostStep,
    RestoreLog, SimulatedDiskExecutor, SystemRestoreExecution, SystemRestoreExecutor,
    UnsupportedSystemRestoreExecutor, DISKPART_SCRIPT_FILE, RESTORE_LIVE_ENV, RESTORE_LOG_FILE,
    RESTORE_LOG_FORMAT_VERSION,
};
pub use system_restore_verify::{
    verify_system_restore, EspBootFileCheck, PartitionVerify, SystemRestoreVerifyReport,
};
pub use volume::{sha256_hex, UnlockedVolume, Volume, VolumeHeader, VOLUME_FORMAT_VERSION};
