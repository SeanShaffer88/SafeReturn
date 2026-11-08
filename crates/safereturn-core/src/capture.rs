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
//! - [`LiveSource`] — logical and actual paths are the same, using the
//!   host's native path syntax. Default for existing callers.
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
use crate::restore_safety::validate_relative_path;
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

    /// The final *logical* root component, never the resolved device name.
    /// The default interprets roots using the host's native path syntax.
    /// Sources accepting another syntax must override this method, so a
    /// selected file keeps its real name rather than a normalized guess.
    fn logical_root_name(&self, root: &Path) -> Result<Option<String>> {
        let text = unicode_path(root)?;
        Ok(root
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            // Preserve the historical display label for roots such as C:\
            // and for "."; there is normally no file at such a root.
            .or_else(|| last_path_segment(text)))
    }

    /// Optional trusted physical anchor for source-path inspection. Its
    /// ancestors, and the anchor itself when opening a descendant, are not
    /// inspected: a caller providing one must establish that it points at
    /// the intended source. Every resolved root must lie beneath it. Without
    /// an anchor, all native ancestors are inspected. Checks are point in
    /// time, not handle-relative or race-free.
    fn inspection_boundary(&self) -> Option<&Path> {
        None
    }

    /// The capture mode manifests must record for sets read through
    /// this source.
    fn capture_mode(&self) -> CaptureMode;
}

/// The live filesystem: logical path = actual path. Existing callers get
/// it by default; names use the host's native path syntax.
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
        // A lossy conversion could resolve a different snapshot file whose
        // name contains the replacement character. Refuse instead.
        let logical = unicode_path(root)?;
        let outside = || CoreError::CaptureRootOutsideVolume {
            root: logical.to_owned(),
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
                part => {
                    // In particular, never push a drive/stream component
                    // like `D:foo`, which has special meaning on Windows.
                    validate_source_component(part, root)?;
                    actual.push(part);
                }
            }
        }
        Ok(actual)
    }

    fn logical_root_name(&self, root: &Path) -> Result<Option<String>> {
        // Snapshot roots use Windows separators even when the mapping is
        // exercised on another host (e.g. in tests or cross-platform tools).
        Ok(last_path_segment(unicode_path(root)?))
    }

    fn inspection_boundary(&self) -> Option<&Path> {
        // The snapshot device object is an opaque, caller-supplied anchor;
        // its virtual GLOBALROOT parents are not ordinary filesystem paths.
        Some(&self.device_root)
    }

    fn capture_mode(&self) -> CaptureMode {
        CaptureMode::VssSnapshot
    }
}

/// Convert only when the *whole logical path* is valid Unicode. The manifest
/// is UTF-8 and must not identify a different path by using replacement text.
pub(crate) fn unicode_path(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| CoreError::BackupPathUnsupported {
            path: path.to_path_buf(),
            reason: "the path is not valid Unicode".to_string(),
        })
}

/// Validate a single source filename, not a pre-normalized path. Slash
/// cannot be part of a native filename, or of a custom logical root name.
pub(crate) fn validate_source_component(name: &str, path: &Path) -> Result<()> {
    if name.contains('/') {
        return Err(CoreError::BackupPathUnsupported {
            path: path.to_path_buf(),
            reason: "a source name contains a path separator".to_string(),
        });
    }
    validate_relative_path(name).map_err(|error| match error {
        CoreError::UnsafeRestorePath { reason, .. } => CoreError::BackupPathUnsupported {
            path: path.to_path_buf(),
            reason,
        },
        other => other,
    })
}

fn last_path_segment(path: &str) -> Option<String> {
    path.split(['\\', '/'])
        .rev()
        .find(|s| !s.is_empty())
        .map(str::to_owned)
}
