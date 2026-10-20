//! SafeReturn S0 spike — VSS requester sequence, platform-agnostic core.
//!
//! The sequence encoded here is Microsoft's documented requester life cycle
//! (Learn: "Requesters", "Overview of Processing a Backup Under VSS",
//! "Overview of Pre-Backup Tasks"):
//!
//!   CreateVssBackupComponents
//!   -> InitializeForBackup
//!   -> SetBackupState(component mode, bootable system state, FULL)
//!   -> GatherWriterMetadata          (Identify event; async, wait + check writers)
//!   -> StartSnapshotSet
//!   -> AddToSnapshotSet (per volume)
//!   -> PrepareForBackup              (async, wait + check writers)
//!   -> DoSnapshotSet                 (PrepareForSnapshot/Freeze/Thaw/PostSnapshot; async)
//!   -> [ read files via snapshot device object ]
//!   -> BackupComplete                (async)
//!   -> Release (object is single-use; never reused — Learn: IVssBackupComponents)
//!
//! On any failure after a snapshot set exists: AbortBackup, then release.
//!
//! This module enforces that order in pure Rust so the *logic* is unit-tested
//! on any OS. The actual COM calls live in `win` (cfg(windows)) and drive this
//! same state machine, so a sequence bug fails a test here instead of
//! corrupting a backup session on a user's PC.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Created,
    Initialized,
    BackupStateSet,
    WriterMetadataGathered,
    SnapshotSetStarted,
    VolumesAdded,
    Prepared,
    SnapshotCreated,
    BackupCompleted,
    Aborted,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VssError {
    /// Mirror of VSS_E_BAD_STATE: call made out of documented sequence.
    BadState {
        expected: &'static str,
        actual: Phase,
        call: &'static str,
    },
    /// Mirror of E_ACCESSDENIED from Create/Initialize: needs admin + backup privilege.
    AccessDenied,
    /// A writer reported a non-retryable / retryable failure at a status check.
    WriterFailed(String),
    Backend(String),
}

impl std::fmt::Display for VssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VssError::BadState { expected, actual, call } => write!(
                f,
                "{call} called in phase {actual:?}; VSS requires {expected} first (VSS_E_BAD_STATE)"
            ),
            VssError::AccessDenied => write!(
                f,
                "access denied: VSS requester must run elevated with backup privilege (E_ACCESSDENIED)"
            ),
            VssError::WriterFailed(w) => write!(f, "VSS writer failed: {w}"),
            VssError::Backend(m) => write!(f, "VSS backend error: {m}"),
        }
    }
}
impl std::error::Error for VssError {}

pub type Result<T> = std::result::Result<T, VssError>;

/// One backup session. Single-use, exactly like IVssBackupComponents:
/// after completion/abort + release it cannot start another backup.
#[derive(Debug)]
pub struct VssSession {
    phase: Phase,
    volumes: Vec<String>,
    snapshot_ids: Vec<String>,
    /// Ordered log of VSS calls, for diagnostics and tests.
    pub call_log: Vec<&'static str>,
}

impl Default for VssSession {
    fn default() -> Self {
        Self::new()
    }
}

impl VssSession {
    pub fn new() -> Self {
        Self {
            phase: Phase::Created,
            volumes: Vec::new(),
            snapshot_ids: Vec::new(),
            call_log: vec!["CreateVssBackupComponents"],
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    fn require(&self, ok: &[Phase], expected: &'static str, call: &'static str) -> Result<()> {
        if ok.contains(&self.phase) {
            Ok(())
        } else {
            Err(VssError::BadState {
                expected,
                actual: self.phase,
                call,
            })
        }
    }

    pub fn initialize_for_backup(&mut self) -> Result<()> {
        self.require(
            &[Phase::Created],
            "CreateVssBackupComponents",
            "InitializeForBackup",
        )?;
        self.call_log.push("InitializeForBackup");
        self.phase = Phase::Initialized;
        Ok(())
    }

    /// SetBackupState(selectComponents=true, bootableSystemState=true,
    /// backupType=FULL, partialFileSupport=false) for the S0/S2 full backup.
    pub fn set_backup_state(&mut self) -> Result<()> {
        self.require(
            &[Phase::Initialized],
            "InitializeForBackup",
            "SetBackupState",
        )?;
        self.call_log
            .push("SetBackupState(FULL, components, bootable)");
        self.phase = Phase::BackupStateSet;
        Ok(())
    }

    pub fn gather_writer_metadata(&mut self) -> Result<()> {
        self.require(
            &[Phase::BackupStateSet],
            "SetBackupState",
            "GatherWriterMetadata",
        )?;
        self.call_log.push("GatherWriterMetadata+Wait");
        self.phase = Phase::WriterMetadataGathered;
        Ok(())
    }

    pub fn start_snapshot_set(&mut self) -> Result<()> {
        self.require(
            &[Phase::WriterMetadataGathered],
            "GatherWriterMetadata",
            "StartSnapshotSet",
        )?;
        self.call_log.push("StartSnapshotSet");
        self.phase = Phase::SnapshotSetStarted;
        Ok(())
    }

    pub fn add_to_snapshot_set(&mut self, volume: &str) -> Result<()> {
        self.require(
            &[Phase::SnapshotSetStarted, Phase::VolumesAdded],
            "StartSnapshotSet",
            "AddToSnapshotSet",
        )?;
        self.call_log.push("AddToSnapshotSet");
        self.volumes.push(volume.to_string());
        self.phase = Phase::VolumesAdded;
        Ok(())
    }

    pub fn prepare_for_backup(&mut self) -> Result<()> {
        self.require(
            &[Phase::VolumesAdded],
            "AddToSnapshotSet (>=1 volume)",
            "PrepareForBackup",
        )?;
        self.call_log.push("PrepareForBackup+Wait");
        self.phase = Phase::Prepared;
        Ok(())
    }

    pub fn do_snapshot_set(&mut self) -> Result<()> {
        self.require(&[Phase::Prepared], "PrepareForBackup", "DoSnapshotSet")?;
        self.call_log.push("DoSnapshotSet+Wait");
        // Snapshot ids are assigned by the provider in the real backend;
        // the state machine records one placeholder per volume.
        self.snapshot_ids = self
            .volumes
            .iter()
            .map(|v| format!("snapshot-of-{v}"))
            .collect();
        self.phase = Phase::SnapshotCreated;
        Ok(())
    }

    pub fn snapshot_ids(&self) -> Result<&[String]> {
        self.require(
            &[Phase::SnapshotCreated],
            "DoSnapshotSet",
            "GetSnapshotProperties",
        )?;
        Ok(&self.snapshot_ids)
    }

    pub fn backup_complete(&mut self) -> Result<()> {
        self.require(&[Phase::SnapshotCreated], "DoSnapshotSet", "BackupComplete")?;
        self.call_log.push("BackupComplete+Wait");
        self.phase = Phase::BackupCompleted;
        Ok(())
    }

    /// Abort is legal any time after creation and before release.
    pub fn abort_backup(&mut self) -> Result<()> {
        self.require(
            &[
                Phase::Initialized,
                Phase::BackupStateSet,
                Phase::WriterMetadataGathered,
                Phase::SnapshotSetStarted,
                Phase::VolumesAdded,
                Phase::Prepared,
                Phase::SnapshotCreated,
            ],
            "an active backup session",
            "AbortBackup",
        )?;
        self.call_log.push("AbortBackup");
        self.phase = Phase::Aborted;
        Ok(())
    }

    pub fn release(&mut self) -> Result<()> {
        if self.phase == Phase::Released {
            return Err(VssError::BadState {
                expected: "a live session",
                actual: self.phase,
                call: "Release",
            });
        }
        self.call_log.push("Release");
        self.phase = Phase::Released;
        Ok(())
    }
}

/// Map a path on the live volume to the same path under the snapshot's
/// device object — how a requester reads a *locked* file from the snapshot
/// instead of the live disk. Pure function; tested cross-platform.
/// e.g. volume `C:\`, file `C:\Users\a\open.db`,
/// device `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12`
///   -> `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy12\Users\a\open.db`
pub fn snapshot_path(volume: &str, snapshot_device: &str, file_on_volume: &str) -> Option<String> {
    let vol = volume.trim_end_matches(['\\', '/']);
    let rest = file_on_volume.strip_prefix(vol)?;
    let rest = rest.trim_start_matches(['\\', '/']);
    if rest.is_empty() {
        return Some(snapshot_device.trim_end_matches(['\\', '/']).to_string());
    }
    Some(format!(
        "{}\\{}",
        snapshot_device.trim_end_matches(['\\', '/']),
        rest.replace('/', "\\")
    ))
}

pub mod session;
pub use session::{SnapshotError, SnapshotSession};

#[cfg(windows)]
pub mod win;
