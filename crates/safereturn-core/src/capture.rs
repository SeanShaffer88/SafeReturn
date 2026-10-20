//! Capture sources: *where a backup reads from* (S3).
//!
//! Until S3 the set walk read the live filesystem directly, which means
//! a file can change — or be locked — while it is being copied. A real
//! system backup reads from a point-in-time snapshot instead. The walk
//! therefore consumes a [`CaptureSource`]: given a root the caller asked
//! for (the *logical* path, e.g. `C:\Users\Sam`), it resolves the path
//! the walk should actually open, and it says how the capture must be
//! described in the set manifest.
//!
//! Two implementations:
//! - [`LiveSource`] — the pre-S3 behavior, unchanged: logical and actual
//!   paths are the same. Default for every existing caller.
//! - [`MappedSource`] — prefix mapping for snapshot capture: logical
//!   paths on one volume (`C:\…`) are opened under a different root —
//!   on Windows, the snapshot's device object
//!   (`\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN`). The mapping
//!   rule is the one proven in the S0 spike (`snapshot_path()` in
//!   safereturn-vss): strip the volume prefix, join the remainder.
//!
//! Invariant the whole design rests on: **manifests record logical
//! paths only.** A snapshot device path is an artifact of one capture
//! session; it must never appear in a set manifest, or restores would
//! depend on a device object that no longer exists.

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// How a set's content was captured. Recorded in every set manifest
/// (S3): a set taken from a snapshot and a set read from the live disk
/// are different promises, and the manifest must say which one it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Read from the live filesystem (files may change during capture).
    Live,
    /// Read from a VSS snapshot of the volume (one point in time).
    VssSnapshot,
}

impl Default for CaptureMode {
    fn default() -> Self {
        // Manifests written before S3 carry no capture_mode; every one
        // of them was a live capture, so Live is the truthful default.
        CaptureMode::Live
    }
}

impl CaptureMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            CaptureMode::Live => "live",
            CaptureMode::VssSnapshot => "vss_snapshot",
        }
    }
}

/// A source the set walk reads through. See the module docs.
pub trait CaptureSource {
    /// Resolve a caller-supplied root to the path the walk should
    /// actually open. For a file root this is the file itself; for a
    /// folder root, everything under it is opened relative to the
    /// returned path.
    fn resolve_root(&self, root: &Path) -> Result<PathBuf>;

    /// The capture mode manifests must record for sets read through
    /// this source.
    fn capture_mode(&self) -> CaptureMode;
}

/// The live filesystem: logical path = actual path. This is exactly the
/// pre-S3 behavior; existing callers get it by default.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveSource;

impl CaptureSource for LiveSource {
    fn resolve_root(&self, root: &Path) -> Result<PathBuf> {
        Ok(root.to_path_buf())
    }

    fn capture_mode(&self) -> CaptureMode {
        CaptureMode::Live
    }
}

/// Prefix-mapped source for snapshot capture. Logical roots on
/// `volume` (e.g. `C:`) are opened under `device_root` (on Windows:
/// the snapshot device object path; in tests: any stand-in directory).
#[derive(Debug, Clone)]
pub struct MappedSource {
    /// Normalized volume designator, e.g. "C:".
    volume: String,
    device_root: PathBuf,
}

impl MappedSource {
    pub fn new(volume: impl Into<String>, device_root: PathBuf) -> Self {
        let raw = volume.into();
        let trimmed = raw.trim_end_matches(['\\', '/']);
        let volume = if trimmed.len() == 1 {
            format!("{trimmed}:")
        } else {
            trimmed.to_string()
        };
        Self {
            volume,
            device_root,
        }
    }

    pub fn volume(&self) -> &str {
        &self.volume
    }

    pub fn device_root(&self) -> &Path {
        &self.device_root
    }
}

impl CaptureSource for MappedSource {
    fn resolve_root(&self, root: &Path) -> Result<PathBuf> {
        let logical = root.to_string_lossy().into_owned();
        let outside = || CoreError::CaptureRootOutsideVolume {
            root: logical.clone(),
            volume: self.volume.clone(),
        };
        // The root must start with the volume designator, followed by
        // a separator or the end of the string ("C:", "C:\…", "C:/…").
        // The drive letter comparison is case-insensitive, as on Windows.
        let prefix_len = self.volume.len();
        match logical.get(..prefix_len) {
            Some(head) if head.eq_ignore_ascii_case(&self.volume) => {}
            _ => return Err(outside()),
        }
        let rest = &logical[prefix_len..];
        if !rest.is_empty() && !rest.starts_with(['\\', '/']) {
            return Err(outside());
        }
        let mut actual = self.device_root.clone();
        for segment in rest.split(['\\', '/']) {
            match segment {
                "" | "." => {}
                // A ".." would escape the snapshot root: the resolved
                // path would no longer be the logical path's content.
                ".." => return Err(outside()),
                part => actual.push(part),
            }
        }
        Ok(actual)
    }

    fn capture_mode(&self) -> CaptureMode {
        CaptureMode::VssSnapshot
    }
}

/// The last segment of a path string, treating both `/` and `\` as
/// separators. Set display names derive from *logical* roots, and a
/// logical root may be written Windows-style (`C:\Users\Sam\Docs`) on
/// any host OS — `Path::file_name` would only split on the host's
/// separator and produce a different (wrong) name in tests and in
/// cross-platform tooling.
pub(crate) fn last_path_segment(path: &Path) -> Option<String> {
    path.to_string_lossy()
        .split(['\\', '/'])
        .rev()
        .find(|s| !s.is_empty())
        .map(|s| s.to_string())
}
