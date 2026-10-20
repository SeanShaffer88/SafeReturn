//! Engine-facing snapshot session (S3): the one object the backup
//! engine holds while it captures from a VSS snapshot.
//!
//! Life cycle:
//!   `begin(volume)`  — create the snapshot (drives the documented
//!                      requester sequence in lib.rs + the C++ helper)
//!   `device_root()`  — where the engine reads: the snapshot's device
//!                      object, fed to the core's `MappedSource`
//!   `finish()`       — BackupComplete, delete the snapshot, release
//!   `abort()`        — AbortBackup, delete the snapshot, release
//!
//! **Dropping a session without finish/abort aborts it.** A snapshot
//! left behind pins disk space (copy-on-write keeps every changed
//! block) and, if the process died mid-capture, "completing" it would
//! record a successful backup for data nobody captured. Abort is the
//! only honest default for an unfinished session; Drop is best-effort
//! (it cannot report errors), so callers should always finish/abort
//! explicitly and treat Drop as the safety net, not the plan.
//!
//! Platform story: `begin` exists on every platform so callers compile
//! everywhere; off Windows it returns
//! [`SnapshotError::UnsupportedPlatform`] — a clean, typed "snapshots
//! require Windows", never a panic or a silent live-capture fallback.
//!
//! STATUS: runtime behavior is UNVERIFIED — no snapshot has been taken
//! by this code on a real Windows machine yet (S0.5 on-machine check).
//! The only runtime exercise is an env-gated, `#[ignore]`d test
//! (`SR_VSS_LIVE=1`); CI never runs it.

use crate::VssError;
#[cfg(windows)]
use crate::VssSession;

#[derive(Debug)]
pub enum SnapshotError {
    /// VSS exists only on Windows; this build is running elsewhere.
    UnsupportedPlatform,
    /// The helper/COM layer failed (message carries the HRESULT text
    /// the helper produced).
    Backend(String),
    /// The state machine rejected a transition. The helper performs
    /// the sequence as one call, so reaching this means the Rust-side
    /// bookkeeping diverged from it — an internal bug, reported as one.
    Sequence(VssError),
}

impl SnapshotError {
    /// Stable machine code (matches the shell contract's error style).
    pub fn code(&self) -> &'static str {
        match self {
            SnapshotError::UnsupportedPlatform => "vss.unsupported_platform",
            SnapshotError::Backend(_) => "vss.snapshot_failed",
            SnapshotError::Sequence(_) => "vss.bad_state",
        }
    }
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::UnsupportedPlatform => write!(
                f,
                "snapshots require Windows: VSS (Volume Shadow Copy Service) exists only on Windows, and this is not Windows. Run the snapshot backup on the Windows PC itself. Nothing was captured."
            ),
            SnapshotError::Backend(m) => write!(
                f,
                "the snapshot could not be taken: {m}. No snapshot backup was made. (SafeReturn never substitutes a live capture for a failed snapshot unless you explicitly allow it.)"
            ),
            SnapshotError::Sequence(e) => {
                write!(f, "internal snapshot sequencing error: {e}")
            }
        }
    }
}
impl std::error::Error for SnapshotError {}

#[cfg(windows)]
struct WinSession {
    machine: VssSession,
    /// Opaque C++ helper session handle (SRVssSession* as void*).
    /// Consumed by exactly one win::finish_snapshot call — the `done`
    /// flag records that consumption, because destroying the helper
    /// session twice would be a double free.
    handle: *mut std::ffi::c_void,
    device_root: String,
    done: bool,
}

/// A live VSS snapshot of one volume, held for the duration of a
/// snapshot capture. See the module docs for the life cycle.
pub struct SnapshotSession {
    volume: String,
    #[cfg(windows)]
    inner: WinSession,
}

impl SnapshotSession {
    /// Take a snapshot of `volume` (e.g. `"C:\\"`). On success the
    /// snapshot exists and stays until finish/abort/drop.
    pub fn begin(volume: &str) -> Result<Self, SnapshotError> {
        #[cfg(not(windows))]
        {
            let _ = volume;
            return Err(SnapshotError::UnsupportedPlatform);
        }
        #[cfg(windows)]
        {
            let (device_root, handle) =
                crate::win::snapshot_volume(volume).map_err(SnapshotError::Backend)?;
            // The helper performed the whole pre-snapshot sequence as
            // one call; drive the state machine through the same steps
            // so its enforced order and call log describe this session.
            // A failure here means the two diverged — an internal bug:
            // tear the helper session down as an abort and say so.
            let mut machine = VssSession::new();
            let sequence = (|| -> Result<(), VssError> {
                machine.initialize_for_backup()?;
                machine.set_backup_state()?;
                machine.gather_writer_metadata()?;
                machine.start_snapshot_set()?;
                machine.add_to_snapshot_set(volume)?;
                machine.prepare_for_backup()?;
                machine.do_snapshot_set()?;
                Ok(())
            })();
            if let Err(e) = sequence {
                let _ = crate::win::finish_snapshot(handle, false);
                return Err(SnapshotError::Sequence(e));
            }
            Ok(Self {
                volume: volume.to_string(),
                inner: WinSession {
                    machine,
                    handle,
                    device_root,
                    done: false,
                },
            })
        }
    }

    /// The volume this session snapshotted, as passed to `begin`.
    pub fn volume(&self) -> &str {
        &self.volume
    }

    /// The snapshot device object the engine reads from
    /// (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`). Only a
    /// session returned by a successful `begin` has one; off Windows
    /// no session can exist, so this is `None` there by construction.
    pub fn device_root(&self) -> Option<&str> {
        #[cfg(windows)]
        {
            Some(&self.inner.device_root)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// Complete the backup: BackupComplete (writers are told the
    /// backup succeeded), delete the snapshot, release. Consumes the
    /// session either way — on error the helper session is torn down
    /// as an abort, because a half-completed snapshot must not linger.
    pub fn finish(mut self) -> Result<(), SnapshotError> {
        #[cfg(not(windows))]
        {
            let _ = &mut self;
            return Err(SnapshotError::UnsupportedPlatform);
        }
        #[cfg(windows)]
        {
            if let Err(e) = self.inner.machine.backup_complete() {
                let _ = crate::win::finish_snapshot(self.inner.handle, false);
                self.inner.done = true;
                return Err(SnapshotError::Sequence(e));
            }
            let result = crate::win::finish_snapshot(self.inner.handle, true)
                .map_err(SnapshotError::Backend);
            self.inner.done = true;
            let _ = self.inner.machine.release();
            result
        }
    }

    /// Abort the backup: AbortBackup, delete the snapshot, release.
    /// Consumes the session either way.
    pub fn abort(mut self) -> Result<(), SnapshotError> {
        #[cfg(not(windows))]
        {
            let _ = &mut self;
            return Err(SnapshotError::UnsupportedPlatform);
        }
        #[cfg(windows)]
        {
            let _ = self.inner.machine.abort_backup();
            let result = crate::win::finish_snapshot(self.inner.handle, false)
                .map_err(SnapshotError::Backend);
            self.inner.done = true;
            let _ = self.inner.machine.release();
            result
        }
    }
}

impl std::fmt::Debug for SnapshotSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl: the Windows inner holds a raw helper handle,
        // which has no useful Debug. Never print the handle itself.
        f.debug_struct("SnapshotSession")
            .field("volume", &self.volume)
            .field("device_root", &self.device_root())
            .finish()
    }
}

impl Drop for SnapshotSession {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            if !self.inner.done {
                // Best-effort abort — see module docs. The helper
                // destroy with complete=false performs AbortBackup +
                // DeleteSnapshots + Release.
                let _ = crate::win::finish_snapshot(self.inner.handle, false);
                self.inner.done = true;
            }
        }
    }
}
