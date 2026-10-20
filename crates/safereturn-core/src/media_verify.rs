//! Media verification and the boot-test marker protocol (S4).
//!
//! `verify_media` answers, from the finished media itself: is the
//! payload intact (re-hashed against `safereturn-media.json`), are
//! the boot files present, and — the fact this product refuses to
//! fudge — **has this media ever actually booted?**
//!
//! Boot-test protocol:
//! - At build time the manifest records `boot_tested` as nothing at
//!   all: absence is the record. Fresh media is *not tested*, and
//!   every surface must say so.
//! - On first boot, the WinPE side (the future PE shell, calling
//!   `record_boot_test` here — one implementation, both sides) writes
//!   `safereturn-boottest.json` to the NTFS (data) partition root:
//!   the media's plan id, when it booted, the firmware type if WinPE
//!   could determine it, and whether the recovery shell was reached.
//! - The host side reads the marker only from the data partition (or
//!   the single root, for a combined check). The media counts as
//!   boot-tested **only** when a marker exists, parses, matches the
//!   manifest's schema version, names *this* media's plan id, and
//!   says the shell was reached. A marker that fails any of that is
//!   reported `Invalid` with the reason — never silently upgraded to
//!   "tested", never silently ignored either.

use crate::error::{io_at, Result};
use crate::media::{read_media_manifest, MediaManifest};
use crate::volume::sha256_hex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const BOOT_TEST_MARKER_FILE: &str = "safereturn-boottest.json";
pub const BOOT_TEST_MARKER_FORMAT_VERSION: u32 = 1;

/// Boot-critical files a MakeWinPEMedia /UFD layout must carry, as
/// media-root-relative paths (checked case-insensitively — FAT32
/// does not preserve the case the ADK wrote).
pub const REQUIRED_BOOT_FILES: [&str; 2] = ["EFI/Boot/bootx64.efi", "sources/boot.wim"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootTestMarker {
    pub format_version: u32,
    /// The plan id of the media that booted (MediaManifest.plan_id).
    pub media_plan_id: String,
    pub booted_unix: u64,
    /// Firmware the machine booted with, as WinPE reported it
    /// ("UEFI", "BIOS", …); None when WinPE could not determine it —
    /// unknown is recorded as unknown, not guessed.
    pub firmware: Option<String>,
    /// Whether boot actually reached the recovery shell. A machine
    /// can boot WinPE and still fail before the shell; that is a
    /// different fact from a full boot test and is reported as one.
    pub reached_shell: bool,
}

/// PE-side: record that this media booted. Called by the recovery
/// shell on first boot (and the shell only — the marker is written
/// from inside WinPE, on the machine that booted, which is what
/// makes it evidence). Temp file + rename, like every SafeReturn
/// write.
pub fn record_boot_test(
    data_root: &Path,
    media_plan_id: &str,
    firmware: Option<String>,
    reached_shell: bool,
    booted_unix: u64,
) -> Result<BootTestMarker> {
    let marker = BootTestMarker {
        format_version: BOOT_TEST_MARKER_FORMAT_VERSION,
        media_plan_id: media_plan_id.to_string(),
        booted_unix,
        firmware,
        reached_shell,
    };
    let path = data_root.join(BOOT_TEST_MARKER_FILE);
    let json = serde_json::to_string_pretty(&marker)
        .map_err(|e| io_at(&path, std::io::Error::other(e.to_string())))?;
    let tmp = data_root.join(format!(".{BOOT_TEST_MARKER_FILE}.tmp"));
    std::fs::write(&tmp, json).map_err(|e| io_at(&tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
    Ok(marker)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootTestStatus {
    /// No marker: this media has never reported a boot. (The normal
    /// state of freshly built media — shown as "not tested yet".)
    NotTested,
    /// A valid marker for this media, shell reached, on record.
    Tested {
        booted_unix: u64,
        firmware: Option<String>,
    },
    /// A marker exists and is valid, but the boot it records did not
    /// reach the recovery shell — a partial result, reported as one.
    BootStartedShellNotReached {
        booted_unix: u64,
        firmware: Option<String>,
    },
    /// A marker file exists but is not valid evidence (unparseable,
    /// wrong schema, or written for different media). Reported with
    /// the reason; never counted as tested.
    Invalid { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadCheck {
    pub dest_rel: String,
    pub ok: bool,
    /// What was found: "present, size and sha256 match" or the named
    /// problem (missing / size differs / content differs).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootFileCheck {
    /// Media-root-relative path that was looked for.
    pub path: String,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaVerifyReport {
    pub manifest: MediaManifest,
    pub payload: Vec<PayloadCheck>,
    pub boot_files: Vec<BootFileCheck>,
    pub boot_test: BootTestStatus,
}

impl MediaVerifyReport {
    pub fn payload_ok(&self) -> bool {
        self.payload.iter().all(|p| p.ok)
    }

    pub fn boot_files_ok(&self) -> bool {
        self.boot_files.iter().all(|b| b.present)
    }

    /// The payload + boot-file verdict. Boot-tested is deliberately
    /// NOT part of this: untested media can be perfectly intact, and
    /// intact media is not thereby boot-tested. Two facts, two fields.
    pub fn passed(&self) -> bool {
        self.payload_ok() && self.boot_files_ok()
    }

    pub fn boot_tested(&self) -> bool {
        matches!(self.boot_test, BootTestStatus::Tested { .. })
    }
}

/// Existence on a case-insensitive filesystem (FAT32): walk the
/// components, matching directory entries case-insensitively, so a
/// check written on Linux means the same thing on the stick.
fn exists_case_insensitive(root: &Path, rel: &str) -> bool {
    let mut current = root.to_path_buf();
    for part in rel.split('/') {
        let exact = current.join(part);
        if exact.exists() {
            current = exact;
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            return false;
        };
        let mut found = None;
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(part)
            {
                found = Some(entry.path());
                break;
            }
        }
        match found {
            Some(p) => current = p,
            None => return false,
        }
    }
    true
}

fn resolve_case_insensitive(root: &Path, rel: &str) -> Option<PathBuf> {
    let mut current = root.to_path_buf();
    for part in rel.split('/') {
        let exact = current.join(part);
        if exact.exists() {
            current = exact;
            continue;
        }
        let entries = std::fs::read_dir(&current).ok()?;
        let mut found = None;
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(part)
            {
                found = Some(entry.path());
                break;
            }
        }
        current = found?;
    }
    Some(current)
}

fn check_payload(boot_root: &Path, entry: &crate::media::PayloadFact) -> PayloadCheck {
    let fail = |detail: String| PayloadCheck {
        dest_rel: entry.dest_rel.clone(),
        ok: false,
        detail,
    };
    // A hand-edited manifest must not be able to point the verifier
    // outside the media root.
    if crate::media::check_dest_rel(&entry.dest_rel).is_err() {
        return fail("manifest entry path is not a clean relative path — not followed".into());
    }
    let Some(path) = resolve_case_insensitive(boot_root, &entry.dest_rel) else {
        return fail("file is missing from the media".into());
    };
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => return fail(format!("file could not be read: {e}")),
    };
    if data.len() as u64 != entry.size_bytes {
        return fail(format!(
            "size differs: manifest says {} bytes, media has {} bytes",
            entry.size_bytes,
            data.len()
        ));
    }
    // Payload entries are app-sized files (engine, shell, config), so
    // a whole-file hash is the right check here.
    let actual = sha256_hex(&data);
    if actual != entry.sha256 {
        return fail(
            "content differs: sha256 does not match the manifest (file was changed or damaged)"
                .into(),
        );
    }
    PayloadCheck {
        dest_rel: entry.dest_rel.clone(),
        ok: true,
        detail: "present, size and sha256 match the manifest".into(),
    }
}

fn read_boot_test(marker_root: &Path, plan_id: &str) -> BootTestStatus {
    let path = marker_root.join(BOOT_TEST_MARKER_FILE);
    if !path.exists() {
        return BootTestStatus::NotTested;
    }
    let invalid = |reason: String| BootTestStatus::Invalid { reason };
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return invalid(format!("marker could not be read: {e}")),
    };
    let marker: BootTestMarker = match serde_json::from_str(&text) {
        Ok(m) => m,
        Err(e) => return invalid(format!("marker is not valid boot-test data: {e}")),
    };
    if marker.format_version != BOOT_TEST_MARKER_FORMAT_VERSION {
        return invalid(format!(
            "marker format {} is not supported (expected {})",
            marker.format_version, BOOT_TEST_MARKER_FORMAT_VERSION
        ));
    }
    if marker.media_plan_id != plan_id {
        return invalid(
            "marker was written for different media (plan id does not match this media's manifest)"
                .into(),
        );
    }
    if marker.reached_shell {
        BootTestStatus::Tested {
            booted_unix: marker.booted_unix,
            firmware: marker.firmware,
        }
    } else {
        BootTestStatus::BootStartedShellNotReached {
            booted_unix: marker.booted_unix,
            firmware: marker.firmware,
        }
    }
}

/// Verify media at a single root (manifest, payload, boot files, and
/// the marker all under `boot_root`). Right for a staged media image
/// or a combined check.
pub fn verify_media(boot_root: &Path) -> Result<MediaVerifyReport> {
    verify_media_roots(boot_root, None)
}

/// Verify built media: manifest/payload/boot files under `boot_root`
/// (the FAT32 partition); the boot-test marker is read from
/// `data_root` (the NTFS partition) when given, else from
/// `boot_root`. A missing manifest is an error (this is not
/// SafeReturn media); everything else is reported as facts.
pub fn verify_media_roots(boot_root: &Path, data_root: Option<&Path>) -> Result<MediaVerifyReport> {
    let manifest = read_media_manifest(boot_root)?;
    let payload = manifest
        .payload
        .iter()
        .map(|e| check_payload(boot_root, e))
        .collect();
    let boot_files = REQUIRED_BOOT_FILES
        .iter()
        .map(|rel| BootFileCheck {
            path: rel.to_string(),
            present: exists_case_insensitive(boot_root, rel),
        })
        .collect();
    let marker_root = data_root.unwrap_or(boot_root);
    let boot_test = read_boot_test(marker_root, &manifest.plan_id);
    Ok(MediaVerifyReport {
        manifest,
        payload,
        boot_files,
        boot_test,
    })
}
