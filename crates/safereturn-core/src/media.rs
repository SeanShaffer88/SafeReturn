//! Recovery-media planning (S4): the pure, cross-platform half of the
//! WinPE media builder. A `MediaPlan` is computed entirely from facts —
//! target device, WinPE source, driver list, payload — and either comes
//! back as an explicit, ordered, confirmable plan or refuses with a
//! named error. Nothing here touches a disk, spawns a tool, or knows
//! what OS it runs on; the executor (media_exec) consumes a plan the
//! user has confirmed, on Windows, later.
//!
//! Layout follows the architecture plan (§5): a two-partition USB —
//! FAT32 boot partition + NTFS remainder — because FAT32 caps files at
//! 4 GB and Windows formats FAT32 to at most 32 GB, while the NTFS side
//! has room for the boot-test marker and future payload growth. Media
//! is produced with the ADK flow (`copype` → DISM servicing →
//! `MakeWinPEMedia`), and `/bootex` is mandatory in the plan so boot
//! files carry the Windows UEFI CA 2023 signature (the 2011 CA is
//! expiring out of Secure Boot trust — plan §5, Microsoft Learn:
//! MakeWinPEMedia command-line options).
//!
//! Every number in a plan is computed from the facts by the formulas
//! in `compute_layout`, with the margins stated there. Nothing is a
//! guess dressed as a measurement: the WinPE facts are supplied by the
//! caller (the CLI reads the real .wim file; the shell will read the
//! real ADK), and each fact is data, not a promise about a machine
//! this code has never seen.

use crate::error::{CoreError, Result};
use crate::volume::sha256_hex;
use serde::{Deserialize, Serialize};

/// Smallest target the builder accepts. Below this, a WinPE boot
/// partition plus a usable NTFS side cannot be laid out honestly.
pub const MIN_TARGET_BYTES: u64 = 8 * 1024 * 1024 * 1024; // 8 GiB

/// Windows will not format FAT32 volumes larger than this, and the
/// architecture plan's two-partition design treats 32 GB as the boot
/// partition's practical ceiling (Microsoft Learn: WinPE single-USB).
pub const FAT32_MAX_BYTES: u64 = 32 * 1024 * 1024 * 1024; // 32 GiB

/// Partitions start on 1 MiB boundaries (the alignment every modern
/// partitioning tool, DiskPart included, uses for flash media).
pub const PARTITION_ALIGNMENT_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Boot partition floor: a serviced WinPE image with the optional
/// components below does not fit in less, and planning smaller would
/// produce media that fails mid-build instead of refusing up front.
pub const MIN_BOOT_PARTITION_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// NTFS remainder floor: below this the data side cannot hold the
/// boot-test marker plus logs with room to spare, so the layout
/// refuses instead of squeezing.
pub const MIN_DATA_PARTITION_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

/// WinPE optional components added to the image, in dependency order
/// (Microsoft Learn: WinPE optional components reference — a
/// component's dependencies must be added before it). Each is here
/// because something in the recovery environment needs it:
///
/// - `WinPE-WMI` — WMI core. The engine's disk/volume facts in WinPE
///   come from WMI storage classes; PowerShell storage cmdlets also
///   sit on it. Added first: almost everything else depends on it.
/// - `WinPE-NetFX` — the .NET subset WinPE supports. No SafeReturn
///   code is .NET; this exists solely because WinPE-PowerShell
///   requires it (documented dependency).
/// - `WinPE-Scripting` — Windows Script Host. Same story: a documented
///   WinPE-PowerShell prerequisite, not something the shells call.
/// - `WinPE-PowerShell` — the operator/diagnostic shell inside WinPE.
///   The guided recovery flow runs documented Windows tools
///   (bcdboot, reagentc, diskpart scripts) and support diagnostics;
///   PowerShell is how those are sequenced and their output captured
///   in the PE environment.
/// - `WinPE-StorageWMI` — storage management WMI providers (disk,
///   partition, volume objects) that the restore target picker and
///   SafeTarget checks query; requires WMI + PowerShell before it.
/// - `WinPE-SecureStartup` — BitLocker/TPM support in WinPE: lets the
///   recovery environment unlock and inspect BitLocker-protected
///   volumes (the plan's BitLocker trap: a restored volume is not
///   auto-re-encrypted, and a locked source volume must be readable
///   with the user's recovery key before anything is restored).
pub const WINPE_OPTIONAL_COMPONENTS: [&str; 6] = [
    "WinPE-WMI",
    "WinPE-NetFX",
    "WinPE-Scripting",
    "WinPE-PowerShell",
    "WinPE-StorageWMI",
    "WinPE-SecureStartup",
];

// ---------------------------------------------------------------------------
// Facts — everything a plan is computed from. Supplied by the caller;
// each field is data the caller measured or the user stated, never a
// default invented here.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaTargetFacts {
    /// Contract disk id (DiskInfo.disk_id) when the shell enumerated
    /// the target; empty when a shell supplied facts directly.
    pub disk_id: String,
    pub model: String,
    /// Last 4 of the serial — identifies the device to a human without
    /// recording the full serial (same rule as DiskInfo).
    pub serial_suffix: String,
    pub size_bytes: u64,
    pub removable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinPeSourceFacts {
    /// Path of winpe.wim in the ADK's WinPE working files (the file
    /// `copype` stages), as supplied by the caller.
    pub wim_path: String,
    pub wim_size_bytes: u64,
    /// Whether the caller actually found the file. A plan is never
    /// built against a WinPE source nobody has seen.
    pub present: bool,
    /// ADK version string as reported by the caller's ADK install
    /// (data, for the record — /bootex requires ADK ≥ 10.1.26100.2454;
    /// the executor refuses older ADKs at build time, on the machine).
    pub adk_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadFact {
    /// Where the file lives now (host path, as supplied).
    pub source_path: String,
    /// Where it goes on the media, relative to the media root, using
    /// '/' separators (e.g. "safereturn/safereturn-pe.exe"). Must be a
    /// clean relative path — planning refuses anything else.
    pub dest_rel: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaFacts {
    pub target: MediaTargetFacts,
    pub winpe: WinPeSourceFacts,
    /// Driver .inf paths captured from this PC, injected into the
    /// image so the recovery environment can see this machine's
    /// storage/network hardware (plan §5).
    pub drivers: Vec<String>,
    pub payload: Vec<PayloadFact>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlanOptions {
    /// Permit a non-removable target (e.g. a fixed USB-attached SSD).
    /// The plan then carries a permanent NonRemovableOverride warning
    /// record — the override is never silent.
    pub allow_non_removable: bool,
}

// ---------------------------------------------------------------------------
// Plan

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaLayout {
    /// Offset of the boot partition from the start of the device.
    pub boot_offset_bytes: u64,
    pub boot_partition_bytes: u64,
    pub data_partition_bytes: u64,
}

/// A warning that is part of the plan itself: it is shown at confirm
/// time, recorded in the plan, and copied into the media manifest, so
/// what the user accepted is provable from the finished media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaWarning {
    /// The target is not removable media and the caller explicitly
    /// overrode the refusal. Erasing the wrong fixed disk is the
    /// classic media-builder disaster; this record is permanent.
    NonRemovableOverride,
}

impl MediaWarning {
    /// Strings-table id (contract style) for shells to render.
    pub fn id(&self) -> &'static str {
        match self {
            MediaWarning::NonRemovableOverride => "media.target_not_removable_override",
        }
    }
}

/// One ordered build step, as data. The executor renders each step to
/// the documented ADK/DISM command (or a file copy) on Windows; the
/// plan itself — and therefore what the user confirms — is identical
/// on every platform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum MediaStep {
    /// `copype <arch>` creates the WinPE working files.
    Copype { arch: String },
    /// DISM mounts boot.wim from the working files for servicing.
    MountImage,
    /// DISM /Add-Package for one optional component (dependency order).
    AddOptionalComponent { name: String },
    /// DISM /Add-Driver for one host driver .inf.
    AddDriver { inf_path: String },
    /// Copy one payload file into the mounted image (so the recovery
    /// shell and engine are on the WinPE RAM disk at boot).
    CopyPayloadToImage {
        source_path: String,
        image_rel: String,
    },
    /// Copy one payload file into the media staging area (so it also
    /// sits at the media root under safereturn/, where the media
    /// manifest can verify it and WinPE can read it from the stick).
    CopyPayloadToMedia {
        source_path: String,
        media_rel: String,
    },
    /// DISM unmounts and commits the serviced image.
    UnmountAndCommit,
    /// MakeWinPEMedia writes the working files to the target device.
    /// `bootex` is always true in plans this builder produces: boot
    /// files signed with the Windows UEFI CA 2023 certificate.
    MakeMedia { bootex: bool },
}

impl MediaStep {
    /// Plain-language line for plan display (the CLI renders these;
    /// shells render their own from the same step data).
    pub fn describe(&self) -> String {
        match self {
            MediaStep::Copype { arch } => {
                format!("Create the WinPE working files (copype {arch})")
            }
            MediaStep::MountImage => "Mount the WinPE image for servicing (DISM)".to_string(),
            MediaStep::AddOptionalComponent { name } => {
                format!("Add the {name} component to WinPE")
            }
            MediaStep::AddDriver { inf_path } => {
                format!("Add this PC's driver: {inf_path}")
            }
            MediaStep::CopyPayloadToImage { image_rel, .. } => {
                format!("Copy recovery app file into the WinPE image: {image_rel}")
            }
            MediaStep::CopyPayloadToMedia { media_rel, .. } => {
                format!("Stage recovery app file on the media: {media_rel}")
            }
            MediaStep::UnmountAndCommit => {
                "Save the serviced WinPE image (DISM unmount + commit)".to_string()
            }
            MediaStep::MakeMedia { bootex } => {
                if *bootex {
                    "Write the media to the target device (MakeWinPEMedia /bootex — UEFI CA 2023 boot files)"
                        .to_string()
                } else {
                    "Write the media to the target device (MakeWinPEMedia)".to_string()
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaPlan {
    /// Deterministic id: SHA-256 of the plan's canonical JSON with
    /// this field blanked. Same facts ⇒ same plan ⇒ same id, on every
    /// machine — a plan can be re-derived and compared, and the media
    /// manifest references the plan it was built from by this id.
    pub plan_id: String,
    pub facts: MediaFacts,
    pub layout: MediaLayout,
    pub optional_components: Vec<String>,
    pub steps: Vec<MediaStep>,
    pub warnings: Vec<MediaWarning>,
    pub payload_total_bytes: u64,
    pub override_non_removable: bool,
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

/// The layout math, stated once and used for both the plan and the
/// tests' expectations:
///
/// - content = winpe.wim bytes + payload bytes (what the boot
///   partition must hold: the serviced image plus the staged payload)
/// - growth margin = 25% of content, rounded up — serviced images
///   grow when optional components are added, and a build that runs
///   out of room mid-copy corrupts silently on some tools; the margin
///   is a stated planning allowance, not a measurement
/// - boot = align_up(max(content + margin, 512 MiB floor), 1 MiB)
/// - boot may not exceed the 32 GiB FAT32 ceiling → refusal
/// - data = target − 1 MiB offset − boot; data < 512 MiB → refusal
fn compute_layout(facts: &MediaFacts) -> Result<(MediaLayout, u64)> {
    let payload_total: u64 = facts.payload.iter().map(|p| p.size_bytes).sum();
    let content = facts.winpe.wim_size_bytes.saturating_add(payload_total);
    let margin = content.div_ceil(4);
    let needed = content.saturating_add(margin);
    let boot = align_up(
        needed.max(MIN_BOOT_PARTITION_BYTES),
        PARTITION_ALIGNMENT_BYTES,
    );
    if boot > FAT32_MAX_BYTES {
        return Err(CoreError::MediaPayloadTooLarge {
            needed_bytes: boot,
            available_bytes: FAT32_MAX_BYTES,
        });
    }
    let offset = PARTITION_ALIGNMENT_BYTES;
    let data = facts
        .target
        .size_bytes
        .saturating_sub(offset)
        .saturating_sub(boot);
    if data < MIN_DATA_PARTITION_BYTES {
        return Err(CoreError::MediaPayloadTooLarge {
            needed_bytes: offset
                .saturating_add(boot)
                .saturating_add(MIN_DATA_PARTITION_BYTES),
            available_bytes: facts.target.size_bytes,
        });
    }
    Ok((
        MediaLayout {
            boot_offset_bytes: offset,
            boot_partition_bytes: boot,
            data_partition_bytes: data,
        },
        payload_total,
    ))
}

fn check_dest_rel(dest_rel: &str) -> Result<()> {
    let bad = dest_rel.is_empty()
        || dest_rel.starts_with('/')
        || dest_rel.starts_with('\\')
        || dest_rel.contains('\\')
        || dest_rel
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if bad {
        return Err(CoreError::MediaInvalidFacts {
            reason: format!(
                "payload destination '{dest_rel}' is not a clean relative path (forward slashes, no '..' or empty parts)"
            ),
        });
    }
    Ok(())
}

/// Compute a media plan from facts, or refuse with a named error.
/// Refusals, in check order: malformed facts (serial suffix, payload
/// paths, empty driver entries), missing WinPE source, target under
/// the 8 GiB minimum, non-removable target without the explicit
/// override, and payload/layout that cannot fit (see compute_layout).
pub fn plan_media(facts: &MediaFacts, options: &MediaPlanOptions) -> Result<MediaPlan> {
    if facts.target.serial_suffix.chars().count() != 4 {
        return Err(CoreError::MediaInvalidFacts {
            reason: format!(
                "target serial suffix must be exactly the last 4 characters, got '{}'",
                facts.target.serial_suffix
            ),
        });
    }
    for p in &facts.payload {
        check_dest_rel(&p.dest_rel)?;
    }
    for d in &facts.drivers {
        if d.trim().is_empty() {
            return Err(CoreError::MediaInvalidFacts {
                reason: "driver list contains an empty path".to_string(),
            });
        }
    }
    if !facts.winpe.present || facts.winpe.wim_size_bytes == 0 {
        return Err(CoreError::MediaSourceMissing {
            detail: format!(
                "the WinPE image was not found at {} — install the Windows ADK with the WinPE add-on, then try again",
                facts.winpe.wim_path
            ),
        });
    }
    if facts.target.size_bytes < MIN_TARGET_BYTES {
        return Err(CoreError::MediaTargetTooSmall {
            size_bytes: facts.target.size_bytes,
            min_bytes: MIN_TARGET_BYTES,
        });
    }
    let mut warnings = Vec::new();
    if !facts.target.removable {
        if !options.allow_non_removable {
            return Err(CoreError::MediaTargetNotRemovable);
        }
        warnings.push(MediaWarning::NonRemovableOverride);
    }

    let (layout, payload_total) = compute_layout(facts)?;

    let mut steps = vec![
        MediaStep::Copype {
            arch: "amd64".to_string(),
        },
        MediaStep::MountImage,
    ];
    for name in WINPE_OPTIONAL_COMPONENTS {
        steps.push(MediaStep::AddOptionalComponent {
            name: name.to_string(),
        });
    }
    for inf in &facts.drivers {
        steps.push(MediaStep::AddDriver {
            inf_path: inf.clone(),
        });
    }
    for p in &facts.payload {
        steps.push(MediaStep::CopyPayloadToImage {
            source_path: p.source_path.clone(),
            image_rel: p.dest_rel.clone(),
        });
        steps.push(MediaStep::CopyPayloadToMedia {
            source_path: p.source_path.clone(),
            media_rel: p.dest_rel.clone(),
        });
    }
    steps.push(MediaStep::UnmountAndCommit);
    steps.push(MediaStep::MakeMedia { bootex: true });

    let mut plan = MediaPlan {
        plan_id: String::new(),
        facts: facts.clone(),
        layout,
        optional_components: WINPE_OPTIONAL_COMPONENTS
            .iter()
            .map(|s| s.to_string())
            .collect(),
        steps,
        warnings,
        payload_total_bytes: payload_total,
        override_non_removable: options.allow_non_removable && !facts.target.removable,
    };
    plan.plan_id = compute_plan_id(&plan)?;
    Ok(plan)
}

fn compute_plan_id(plan: &MediaPlan) -> Result<String> {
    let mut blanked = plan.clone();
    blanked.plan_id = String::new();
    let json = serde_json::to_string(&blanked).map_err(|e| CoreError::MediaInvalidFacts {
        reason: format!("plan could not be serialized for id computation: {e}"),
    })?;
    Ok(sha256_hex(json.as_bytes()))
}
