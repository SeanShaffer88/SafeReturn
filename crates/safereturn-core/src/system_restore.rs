//! System (bare-metal) restore planning (S5): given a *system*
//! backup set (S3 manifest with a system-facts section) and the
//! facts of a blank or replaceable target disk, compute the complete
//! restore as inspectable data — the GPT partition layout, which set
//! file lands on which partition, and the post-apply system steps
//! (bcdboot, reagentc, user notices) — or refuse with a named error.
//!
//! This module is pure and cross-platform: it reads nothing and
//! writes nothing. Execution lives in `system_restore_exec` behind
//! the engine's plan-token flow (slice 2), verification in
//! `system_restore_verify` (slice 3).
//!
//! Layout contract (all math computed here, every default sourced —
//! see docs/S5_NOTES.md for the full citations):
//! - GPT, UEFI only. A BIOS source, an unknown firmware mode on
//!   either side, or a source/target firmware mismatch is a typed
//!   refusal — a restore is never silently converted.
//! - ESP: FAT32. 300 MiB default — Microsoft Learn, "UEFI/GPT-based
//!   hard drive partitions", sets the ESP minimum at 200 MB for
//!   512-byte-sector drives and 300 MB for 4K-native drives; the
//!   default covers both. If the set's recorded ESP contents plus a
//!   stated 32 MiB headroom exceed the default, the ESP grows to fit
//!   the contents instead.
//! - MSR: 16 MiB (same Learn document: "The size of the MSR is
//!   16 MB").
//! - Windows RE tools partition (when the source had WinRE and the
//!   set carries its image): at least 300 MiB, and the image size
//!   plus 200 MiB of free space — Microsoft Learn / KB 3135522:
//!   the partition "must be at least 300 megabytes", and for
//!   Windows 10 version 2004 and later it "must have at least
//!   200 MB of free space". Type id and GPT attributes are the
//!   documented Windows RE values.
//! - Windows partition: everything left after the fixed partitions
//!   and a 1 MiB end reserve (backup GPT). It must hold the set's OS
//!   data plus free-space headroom of max(10% of that data, 512 MiB)
//!   — a stated planning allowance (a freshly restored Windows needs
//!   room for its page file and first updates), not a measurement.
//!   A target that cannot hold layout + data + headroom is refused
//!   before anything is erased.
//!
//! Set-content mapping is explicit, never guessed: the caller names
//! which manifest root is the Windows volume and which is the ESP
//! capture. Files under any other recorded root refuse the plan —
//! a bare-metal restore never silently drops backed-up content.
//! A set with no WinRE image still plans (the gap is a disclosed
//! plan warning); a set whose ESP content lacks the boot files is
//! refused — it could only produce an unbootable disk.

use crate::error::{CoreError, Result};
use crate::sets::{SetFileEntry, SetManifest};
use crate::system::{BitLockerState, BootMode, Fact};
use crate::volume::sha256_hex;
use serde::{Deserialize, Serialize};

const MIB: u64 = 1024 * 1024;

/// GPT structures at the start of the disk (protective MBR, primary
/// header and entries), aligned up to 1 MiB like every layout here.
pub const GPT_FRONT_RESERVE_BYTES: u64 = MIB;
/// Room for the backup GPT at the end of the disk.
pub const GPT_END_RESERVE_BYTES: u64 = MIB;
/// Default ESP size: covers both Microsoft Learn ESP minimums
/// (200 MB for 512-byte sectors, 300 MB for 4K-native). See the
/// module docs.
pub const ESP_DEFAULT_BYTES: u64 = 300 * MIB;
/// Stated allowance added to the recorded ESP contents when they
/// outgrow the default: room for the BCD store bcdboot writes and
/// for firmware files added later.
pub const ESP_CONTENT_HEADROOM_BYTES: u64 = 32 * MIB;
/// MSR size: Microsoft Learn, "UEFI/GPT-based hard drive partitions".
pub const MSR_BYTES: u64 = 16 * MIB;
/// Windows RE tools partition minimum: Microsoft Learn / KB 3135522.
pub const WINRE_MIN_BYTES: u64 = 300 * MIB;
/// Free space a post-2004 Windows RE partition must keep after the
/// image: Microsoft Learn / KB 3135522 (200 MB).
pub const WINRE_FREE_HEADROOM_BYTES: u64 = 200 * MIB;
/// Windows-partition free-space headroom floor (stated planning
/// allowance; the headroom is max(10% of OS data, this floor)).
pub const WINDOWS_HEADROOM_MIN_BYTES: u64 = 512 * MIB;

/// GPT partition type GUIDs (Microsoft Learn, "UEFI/GPT-based hard
/// drive partitions" and KB 3135522 for the Windows RE tools type).
pub const ESP_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const MSR_TYPE_GUID: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
pub const BASIC_DATA_TYPE_GUID: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
pub const WINRE_TYPE_GUID: &str = "de94bba4-06d1-4d40-a16a-bfd50179d6ac";
/// GPT attributes for the Windows RE tools partition:
/// GPT_ATTRIBUTE_PLATFORM_REQUIRED (0x1) +
/// GPT_BASIC_DATA_ATTRIBUTE_NO_DRIVE_LETTER (0x8000000000000000),
/// per the Microsoft Learn DiskPart sample for UEFI/GPT layouts.
pub const WINRE_GPT_ATTRIBUTES: &str = "0x8000000000000001";

/// Files a UEFI ESP must carry for the restored disk to boot, as
/// paths inside the ESP ('/' separators, compared case-insensitively
/// — FAT32 paths are case-insensitive and captures preserve the
/// source's casing). bootmgfw.efi is the Windows Boot Manager;
/// bootx64.efi is the removable-media/default fallback path the
/// firmware opens (UEFI 2.3.1, cited in Microsoft Learn's BCDBoot
/// options). bcdboot also regenerates boot-environment files from
/// the Windows partition, but a set that captured neither boot
/// manager is not a system backup in any usable sense — the plan
/// refuses rather than hoping bcdboot can compensate.
pub const REQUIRED_ESP_BOOT_FILES: [&str; 2] =
    ["EFI/Microsoft/Boot/bootmgfw.efi", "EFI/Boot/bootx64.efi"];

/// Where the WinRE image is placed on the recovery partition
/// (path inside that partition, '/' separators). Matches the layout
/// `reagentc /setreimage` is pointed at.
pub const WINRE_IMAGE_DEST_REL: &str = "Recovery/WindowsRE/Winre.wim";
/// The path (inside the OS volume, '/' separators, matched
/// case-insensitively) where a running Windows keeps its staged
/// WinRE image — the primary place the planner looks for it.
const WINRE_STAGED_REL: &str = "Windows/System32/Recovery/Winre.wim";

/// Facts about the disk that would be erased, as the caller (shell /
/// CLI) determined them. Only the last 4 characters of the serial are
/// ever carried — enough for a human to confirm the device, never
/// the whole identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRestoreTargetFacts {
    pub disk_id: String,
    pub model: String,
    /// Exactly the last 4 characters of the serial number.
    pub serial_suffix: String,
    pub size_bytes: u64,
    pub removable: bool,
    /// Firmware mode of the machine that will boot the restored
    /// disk, as a sourced fact. Unknown is refused at plan time.
    pub firmware: Fact<BootMode>,
}

/// Caller-named mapping from the set's recorded roots to partitions.
/// Explicit by design: the planner never guesses which captured
/// folder was the ESP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRestoreOptions {
    /// Manifest root display name of the Windows volume capture.
    pub os_root: String,
    /// Manifest root display name of the ESP capture.
    pub esp_root: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionRole {
    Esp,
    Msr,
    Windows,
    WinRe,
}

impl PartitionRole {
    /// Directory name for this partition on a directory-backed
    /// (simulated) disk, and the label verification uses.
    pub fn dir_name(&self) -> &'static str {
        match self {
            PartitionRole::Esp => "esp",
            PartitionRole::Msr => "msr",
            PartitionRole::Windows => "windows",
            PartitionRole::WinRe => "winre",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PartitionFilesystem {
    Fat32,
    Ntfs,
}

/// One partition of the computed layout. Sizes and offsets are
/// bytes; `size_source` states where the size came from (a recorded
/// fact, or the documented default) — a layout a user cannot
/// interrogate is a layout they cannot trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionSpec {
    /// 1-based GPT partition number, in on-disk order.
    pub index: u32,
    pub role: PartitionRole,
    pub offset_bytes: u64,
    pub size_bytes: u64,
    /// None only for the MSR, which is never formatted.
    pub filesystem: Option<PartitionFilesystem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub type_guid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpt_attributes: Option<String>,
    /// Letter the executor assigns in WinPE so later steps can name
    /// the partition (the letters in Microsoft's documented samples:
    /// S for the system partition, W for Windows, R for recovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drive_letter: Option<char>,
    /// Provenance of `size_bytes`, in words.
    pub size_source: String,
}

/// One file application: set content → a path inside a target
/// partition. Applying a plan means writing each of these (content
/// rebuilt from the set's chunks and hash-verified before write, by
/// the same restore path file restores use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyFileStep {
    pub partition: PartitionRole,
    /// Path inside the set ("<root>/<relative path>").
    pub set_path: String,
    /// Path inside the target partition ('/' separators).
    pub dest_rel: String,
    pub size: u64,
    pub sha256: String,
}

/// A post-apply system step, as data. Command steps render to exact
/// argv via `command()`; notice steps are shown to the user and
/// recorded — they exist because a restore that finishes silently
/// on these points has misled the user (see S5_NOTES).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum SystemRestorePostStep {
    /// Create the boot files + BCD store on the new ESP from the
    /// restored Windows installation. Microsoft Learn, "BCDBoot
    /// Command-Line Options": /f requires /s; with /s the firmware
    /// NVRAM entry is not created and the firmware's default path
    /// (\EFI\Boot\bootx64.efi, which the ESP application places)
    /// is what boots the disk.
    Bcdboot {
        /// e.g. "W:\\Windows"
        windows_dir: String,
        /// e.g. "S:"
        system_partition: String,
        firmware: BootMode,
    },
    /// Point Windows RE at the image placed on the recovery
    /// partition. Microsoft Learn, "REAgentC command-line options":
    /// /setreimage /path <dir> [/target <offline Windows dir>];
    /// /target is the offline form used from WinPE.
    ReagentcSetReImage {
        /// e.g. "R:\\Recovery\\WindowsRE"
        path: String,
        /// e.g. "W:\\Windows"
        target: String,
    },
    /// Enable Windows RE (after SetReImage). Same Learn document.
    ReagentcEnable,
    /// Shown to the user, recorded in the restore log; not a command.
    Notice { id: String, text: String },
}

impl SystemRestorePostStep {
    /// Exact argv for command steps; `None` for notices.
    pub fn command(&self) -> Option<Vec<String>> {
        match self {
            SystemRestorePostStep::Bcdboot {
                windows_dir,
                system_partition,
                firmware,
            } => Some(vec![
                "bcdboot".to_string(),
                windows_dir.clone(),
                "/s".to_string(),
                system_partition.clone(),
                "/f".to_string(),
                match firmware {
                    BootMode::Uefi => "UEFI".to_string(),
                    BootMode::Bios => "BIOS".to_string(),
                },
            ]),
            SystemRestorePostStep::ReagentcSetReImage { path, target } => Some(vec![
                "reagentc".to_string(),
                "/setreimage".to_string(),
                "/path".to_string(),
                path.clone(),
                "/target".to_string(),
                target.clone(),
            ]),
            SystemRestorePostStep::ReagentcEnable => {
                Some(vec!["reagentc".to_string(), "/enable".to_string()])
            }
            SystemRestorePostStep::Notice { .. } => None,
        }
    }

    /// Plain-language rendering for shells, CLI output, and the
    /// restore log.
    pub fn describe(&self) -> String {
        match self {
            SystemRestorePostStep::Bcdboot { .. } => {
                "Create the boot files and boot configuration on the new EFI System Partition (bcdboot)".to_string()
            }
            SystemRestorePostStep::ReagentcSetReImage { path, .. } => format!(
                "Register the Windows Recovery Environment image at {path} (reagentc /setreimage)"
            ),
            SystemRestorePostStep::ReagentcEnable => {
                "Enable the Windows Recovery Environment (reagentc /enable)".to_string()
            }
            SystemRestorePostStep::Notice { text, .. } => text.clone(),
        }
    }
}

/// A disclosed gap or consequence of the plan. Warnings never block
/// planning (refusals are errors); they are part of what the user
/// confirms, they ride into the plan summary, and they are recorded
/// with the executed restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "warning", rename_all = "snake_case")]
pub enum SystemRestoreWarning {
    /// The restored PC will have no working Windows Recovery
    /// Environment: either the source had none, its presence was not
    /// recorded, or the set does not carry its image. Proceeding is
    /// allowed only with this named — a restore that silently loses
    /// WinRE is a failed restore.
    WinReMissing { detail: String },
    /// The source PC had BitLocker on for these volumes. VSS reads
    /// an unlocked volume, so the backup is plaintext inside its
    /// encryption; the restored volume is NOT BitLocker-protected.
    BitLockerNotRestored { volumes: Vec<String> },
    /// BitLocker state for these volumes was recorded as unknown —
    /// whether the source was protected could not be confirmed.
    BitLockerStateUnknown { volumes: Vec<String> },
    /// Secure Boot state of the source was recorded as unknown.
    SecureBootStateUnknown { detail: String },
    /// The set's ESP files differ from the ESP listing recorded in
    /// the system facts (missing, extra, or different). The set's
    /// files are what get applied; the drift is disclosed.
    EspFactsMismatch { detail: String },
}

impl SystemRestoreWarning {
    pub fn id(&self) -> &'static str {
        match self {
            SystemRestoreWarning::WinReMissing { .. } => "system_restore.winre_missing",
            SystemRestoreWarning::BitLockerNotRestored { .. } => {
                "system_restore.bitlocker_not_restored"
            }
            SystemRestoreWarning::BitLockerStateUnknown { .. } => {
                "system_restore.bitlocker_state_unknown"
            }
            SystemRestoreWarning::SecureBootStateUnknown { .. } => {
                "system_restore.secure_boot_state_unknown"
            }
            SystemRestoreWarning::EspFactsMismatch { .. } => "system_restore.esp_facts_mismatch",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            SystemRestoreWarning::WinReMissing { detail } => {
                format!("Windows Recovery Environment will not be restored: {detail}")
            }
            SystemRestoreWarning::BitLockerNotRestored { volumes } => format!(
                "BitLocker was on for {} on the source PC. The restored disk is NOT encrypted — turn BitLocker on again after the PC first starts.",
                volumes.join(", ")
            ),
            SystemRestoreWarning::BitLockerStateUnknown { volumes } => format!(
                "Whether BitLocker was on for {} could not be determined from the backup. The restored disk will not be encrypted either way; check after the PC first starts.",
                volumes.join(", ")
            ),
            SystemRestoreWarning::SecureBootStateUnknown { detail } => format!(
                "Secure Boot state of the source PC is unknown ({detail}). If the target PC has Secure Boot on and rejects the restored boot files, adjust Secure Boot in the firmware setup."
            ),
            SystemRestoreWarning::EspFactsMismatch { detail } => format!(
                "The EFI System Partition files in the backup differ from the listing recorded when it was captured: {detail}. The files in the backup are what will be applied."
            ),
        }
    }
}

/// The complete, inspectable system-restore plan. Deterministic:
/// the same manifest, target facts, and options produce the same
/// plan (and the same `plan_id`) on every machine, so a plan made
/// in one place can be re-derived and compared in another — the
/// CLI's stateless confirmation flow depends on this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemRestorePlan {
    /// Deterministic id: SHA-256 of the plan's canonical JSON with
    /// this field blanked (same scheme as MediaPlan).
    pub plan_id: String,
    pub set_id: String,
    pub target: SystemRestoreTargetFacts,
    /// The firmware mode the layout and boot steps are built for —
    /// always the source's mode, and (enforced at plan time) equal
    /// to the target machine's.
    pub firmware: BootMode,
    /// Partitions in on-disk order (index 1..=n).
    pub layout: Vec<PartitionSpec>,
    /// Smallest target this plan fits: fixed partitions + OS data +
    /// headroom + reserves. The given target met it (planning
    /// refuses otherwise); it is recorded for the summary.
    pub required_min_bytes: u64,
    /// Bytes of OS-partition data the plan applies.
    pub os_bytes: u64,
    /// Bytes of ESP data the plan applies.
    pub esp_bytes: u64,
    /// Every file application, ordered by partition then path.
    pub applications: Vec<ApplyFileStep>,
    /// ESP files (paths inside the ESP) whose presence verification
    /// must confirm — copied from REQUIRED_ESP_BOOT_FILES.
    pub required_boot_files: Vec<String>,
    pub post_steps: Vec<SystemRestorePostStep>,
    pub warnings: Vec<SystemRestoreWarning>,
}

impl SystemRestorePlan {
    pub fn partition(&self, role: PartitionRole) -> Option<&PartitionSpec> {
        self.layout.iter().find(|p| p.role == role)
    }

    pub fn total_file_count(&self) -> u64 {
        self.applications.len() as u64
    }

    pub fn total_apply_bytes(&self) -> u64 {
        self.applications.iter().map(|a| a.size).sum()
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn invalid(reason: String) -> CoreError {
    CoreError::SystemRestoreInvalidFacts { reason }
}

/// Compute a system restore plan, or refuse with a named error.
/// Refusal order: malformed target facts → set is not a system set →
/// firmware refusals (unsupported / unknown / mismatch) → root
/// mapping problems → missing boot content → target too small.
pub fn plan_system_restore(
    manifest: &SetManifest,
    target: &SystemRestoreTargetFacts,
    options: &SystemRestoreOptions,
) -> Result<SystemRestorePlan> {
    if target.serial_suffix.chars().count() != 4 {
        return Err(invalid(format!(
            "target serial suffix must be exactly the last 4 characters, got '{}'",
            target.serial_suffix
        )));
    }
    if target.disk_id.trim().is_empty() {
        return Err(invalid("target disk id is empty".to_string()));
    }

    let facts = manifest
        .system
        .as_ref()
        .ok_or_else(|| CoreError::SystemRestoreNotASystemSet {
            set_id: manifest.set_id.clone(),
        })?;
    facts.validate()?;

    // -- Firmware: the plan is UEFI/GPT. Anything else is refused,
    //    never converted and never guessed.
    let source_mode = match &facts.boot_mode.value {
        Some(BootMode::Uefi) => BootMode::Uefi,
        Some(BootMode::Bios) => {
            return Err(CoreError::SystemRestoreFirmwareUnsupported {
                detail: "the source PC booted in BIOS mode (recorded in the backup's system facts). SafeReturn's whole-PC restore builds UEFI/GPT disks; a BIOS/MBR restore is not supported by this build".to_string(),
            });
        }
        None => {
            return Err(CoreError::SystemRestoreFirmwareUnknown {
                detail: format!(
                    "the backup's system facts do not record the source PC's firmware mode ({})",
                    facts
                        .boot_mode
                        .unknown_reason
                        .clone()
                        .unwrap_or_else(|| "no reason recorded".to_string())
                ),
            });
        }
    };
    match &target.firmware.value {
        Some(m) if *m == source_mode => {}
        Some(m) => {
            return Err(CoreError::SystemRestoreFirmwareMismatch {
                detail: format!(
                    "the backup was captured from a {source_mode:?} PC, and this target PC boots in {m:?} mode"
                ),
            });
        }
        None => {
            return Err(CoreError::SystemRestoreFirmwareUnknown {
                detail: format!(
                    "the target PC's firmware mode could not be determined ({})",
                    target
                        .firmware
                        .unknown_reason
                        .clone()
                        .unwrap_or_else(|| "no reason recorded".to_string())
                ),
            });
        }
    }

    // -- Root mapping: explicit, and every recorded root accounted for.
    if options.os_root == options.esp_root {
        return Err(invalid(format!(
            "the OS root and the ESP root are both '{}' — they must be two different captured folders",
            options.os_root
        )));
    }
    for (what, name) in [("OS", &options.os_root), ("ESP", &options.esp_root)] {
        if !manifest.roots.iter().any(|r| r == name) {
            return Err(invalid(format!(
                "the {what} root '{name}' is not one of the roots recorded in the set ({})",
                manifest.roots.join(", ")
            )));
        }
    }

    // -- Classify the set's files by their root.
    let mut os_entries: Vec<&SetFileEntry> = Vec::new();
    let mut esp_entries: Vec<&SetFileEntry> = Vec::new();
    for entry in &manifest.files {
        let (root, _rel) = match entry.path.split_once('/') {
            Some((root, rel)) if !rel.is_empty() => (root, rel),
            _ => {
                return Err(invalid(format!(
                    "set file '{}' is not under a recorded root",
                    entry.path
                )))
            }
        };
        if root == options.os_root {
            os_entries.push(entry);
        } else if root == options.esp_root {
            esp_entries.push(entry);
        } else if manifest.roots.iter().any(|r| r == root) {
            return Err(invalid(format!(
                "the set also contains the root '{root}', which is not mapped to a partition. A whole-PC restore covers only the OS and ESP roots, and it never drops backed-up files silently. Restore '{root}' separately with a file restore, or re-capture the system set without it."
            )));
        } else {
            return Err(invalid(format!(
                "set file '{}' is under root '{root}', which the set does not record",
                entry.path
            )));
        }
    }
    if os_entries.is_empty() {
        return Err(invalid(format!(
            "the set contains no files under the OS root '{}'",
            options.os_root
        )));
    }

    // -- ESP content: present, bootable, and consistent with the
    //    recorded ESP listing when there is one.
    if esp_entries.is_empty() {
        return Err(CoreError::SystemRestoreBootFilesMissing {
            detail: format!(
                "the set contains no files under the ESP root '{}'",
                options.esp_root
            ),
        });
    }
    let esp_rel_lower: Vec<String> = esp_entries
        .iter()
        .map(|e| rel_of(e, &options.esp_root).to_lowercase())
        .collect();
    let missing_boot: Vec<&str> = REQUIRED_ESP_BOOT_FILES
        .iter()
        .filter(|req| !esp_rel_lower.iter().any(|r| r == &req.to_lowercase()))
        .copied()
        .collect();
    if !missing_boot.is_empty() {
        return Err(CoreError::SystemRestoreBootFilesMissing {
            detail: format!(
                "the captured EFI System Partition is missing {}",
                missing_boot.join(", ")
            ),
        });
    }

    let mut warnings: Vec<SystemRestoreWarning> = Vec::new();
    if let Some(listed) = &facts.esp_files.value {
        let mut problems: Vec<String> = Vec::new();
        for f in listed {
            match esp_entries
                .iter()
                .find(|e| rel_of(e, &options.esp_root) == f.path)
            {
                Some(e) if e.size == f.size && e.sha256 == f.sha256 => {}
                Some(_) => problems.push(format!("{} (different content)", f.path)),
                None => problems.push(format!("{} (not in the set)", f.path)),
            }
        }
        for e in &esp_entries {
            let rel = rel_of(e, &options.esp_root);
            if !listed.iter().any(|f| f.path == rel) {
                problems.push(format!("{rel} (in the set, not in the recorded listing)"));
            }
        }
        if !problems.is_empty() {
            warnings.push(SystemRestoreWarning::EspFactsMismatch {
                detail: problems.join("; "),
            });
        }
    }

    // -- WinRE: place the image when the set carries it; name the
    //    gap (as a warning, not a refusal) when it does not. An
    //    image found in the set is placed even when the facts
    //    disagreed — content evidence wins, and the warning below
    //    discloses the disagreement either way.
    let winre_entry = find_winre_image(&os_entries, options);
    let winre_included = winre_entry.is_some();
    match (&facts.winre.value, winre_included) {
        (Some(info), true) if info.present => {}
        (Some(_), true) => {
            warnings.push(SystemRestoreWarning::WinReMissing {
                detail: "the backup's system facts recorded no Windows Recovery Environment on the source PC, but the backup does contain a WinRE image, which will be placed and registered".to_string(),
            });
        }
        (Some(info), false) if info.present => {
            warnings.push(SystemRestoreWarning::WinReMissing {
                detail: format!(
                    "the source PC had a Windows Recovery Environment ({}), but the backup does not contain its image (Winre.wim), so it cannot be restored",
                    info.location
                        .clone()
                        .unwrap_or_else(|| "location not recorded".to_string())
                ),
            });
        }
        (Some(_), false) => {
            warnings.push(SystemRestoreWarning::WinReMissing {
                detail: "the source PC had no Windows Recovery Environment recorded, and the backup contains no WinRE image, so the restored PC will not have one either".to_string(),
            });
        }
        (None, found) => {
            warnings.push(SystemRestoreWarning::WinReMissing {
                detail: format!(
                    "whether the source PC had a Windows Recovery Environment was not recorded ({}){}",
                    facts
                        .winre
                        .unknown_reason
                        .clone()
                        .unwrap_or_else(|| "no reason recorded".to_string()),
                    if found {
                        "; an image was found in the backup and will be placed and registered"
                    } else {
                        ", and no image was found in the backup, so the restored PC will not have one"
                    }
                ),
            });
        }
    }
    let winre_image_bytes = if winre_included {
        winre_entry.map(|e| e.size).unwrap_or(0)
    } else {
        0
    };

    // -- BitLocker + Secure Boot disclosures.
    let mut protected: Vec<String> = Vec::new();
    let mut bitlocker_unknown: Vec<String> = Vec::new();
    for (volume_name, fact) in &facts.bitlocker {
        match &fact.value {
            Some(BitLockerState::On) | Some(BitLockerState::Suspended) => {
                protected.push(volume_name.clone())
            }
            Some(BitLockerState::Off) => {}
            None => bitlocker_unknown.push(volume_name.clone()),
        }
    }
    if !protected.is_empty() {
        warnings.push(SystemRestoreWarning::BitLockerNotRestored {
            volumes: protected.clone(),
        });
    }
    if !bitlocker_unknown.is_empty() {
        warnings.push(SystemRestoreWarning::BitLockerStateUnknown {
            volumes: bitlocker_unknown,
        });
    }
    let secure_boot_on = facts.secure_boot.value == Some(true);
    if facts.secure_boot.value.is_none() {
        warnings.push(SystemRestoreWarning::SecureBootStateUnknown {
            detail: facts
                .secure_boot
                .unknown_reason
                .clone()
                .unwrap_or_else(|| "no reason recorded".to_string()),
        });
    }

    // -- Layout math (all computed; sources in size_source fields).
    let esp_bytes: u64 = esp_entries.iter().map(|e| e.size).sum();
    let esp_size = align_up(
        (esp_bytes + ESP_CONTENT_HEADROOM_BYTES).max(ESP_DEFAULT_BYTES),
        MIB,
    );
    let esp_size_source = if esp_bytes + ESP_CONTENT_HEADROOM_BYTES > ESP_DEFAULT_BYTES {
        format!(
            "sized from the ESP contents recorded in the backup ({esp_bytes} bytes) plus a stated 32 MiB headroom for the boot configuration bcdboot writes"
        )
    } else {
        "300 MiB default — Microsoft Learn, \"UEFI/GPT-based hard drive partitions\": the ESP minimum is 200 MB on 512-byte-sector drives and 300 MB on 4K-native drives; the default covers both".to_string()
    };
    let winre_size = if winre_included {
        align_up(
            (winre_image_bytes + WINRE_FREE_HEADROOM_BYTES).max(WINRE_MIN_BYTES),
            MIB,
        )
    } else {
        0
    };
    let os_bytes: u64 = os_entries.iter().map(|e| e.size).sum();
    let headroom = (os_bytes / 10).max(WINDOWS_HEADROOM_MIN_BYTES);
    let required_min_bytes = GPT_FRONT_RESERVE_BYTES
        + esp_size
        + MSR_BYTES
        + winre_size
        + os_bytes
        + headroom
        + GPT_END_RESERVE_BYTES;
    if target.size_bytes < required_min_bytes {
        return Err(CoreError::SystemRestoreTargetTooSmall {
            needed_bytes: required_min_bytes,
            size_bytes: target.size_bytes,
        });
    }
    let windows_size = target.size_bytes
        - GPT_FRONT_RESERVE_BYTES
        - esp_size
        - MSR_BYTES
        - winre_size
        - GPT_END_RESERVE_BYTES;

    let mut layout: Vec<PartitionSpec> = Vec::new();
    let mut offset = GPT_FRONT_RESERVE_BYTES;
    let mut index = 1u32;
    layout.push(PartitionSpec {
        index,
        role: PartitionRole::Esp,
        offset_bytes: offset,
        size_bytes: esp_size,
        filesystem: Some(PartitionFilesystem::Fat32),
        label: Some("System".to_string()),
        type_guid: ESP_TYPE_GUID.to_string(),
        gpt_attributes: None,
        drive_letter: Some('S'),
        size_source: esp_size_source,
    });
    offset += esp_size;
    index += 1;
    layout.push(PartitionSpec {
        index,
        role: PartitionRole::Msr,
        offset_bytes: offset,
        size_bytes: MSR_BYTES,
        filesystem: None,
        label: None,
        type_guid: MSR_TYPE_GUID.to_string(),
        gpt_attributes: None,
        drive_letter: None,
        size_source: "16 MiB — Microsoft Learn, \"UEFI/GPT-based hard drive partitions\": \"The size of the MSR is 16 MB\"".to_string(),
    });
    offset += MSR_BYTES;
    index += 1;
    layout.push(PartitionSpec {
        index,
        role: PartitionRole::Windows,
        offset_bytes: offset,
        size_bytes: windows_size,
        filesystem: Some(PartitionFilesystem::Ntfs),
        label: Some("Windows".to_string()),
        type_guid: BASIC_DATA_TYPE_GUID.to_string(),
        gpt_attributes: None,
        drive_letter: Some('W'),
        size_source: format!(
            "the rest of the target disk after the fixed partitions and the end reserve; holds {os_bytes} bytes of restored data plus {headroom} bytes of headroom (the larger of 10% of the data or 512 MiB — a stated planning allowance for the page file and first updates, not a measurement)"
        ),
    });
    offset += windows_size;
    index += 1;
    if winre_included {
        layout.push(PartitionSpec {
            index,
            role: PartitionRole::WinRe,
            offset_bytes: offset,
            size_bytes: winre_size,
            filesystem: Some(PartitionFilesystem::Ntfs),
            label: Some("Windows RE tools".to_string()),
            type_guid: WINRE_TYPE_GUID.to_string(),
            gpt_attributes: Some(WINRE_GPT_ATTRIBUTES.to_string()),
            drive_letter: Some('R'),
            size_source: format!(
                "Winre.wim ({winre_image_bytes} bytes) plus 200 MiB of free space, minimum 300 MiB — Microsoft Learn / KB 3135522: a Windows RE tools partition \"must be at least 300 megabytes\" and, for Windows 10 version 2004 and later, \"must have at least 200 MB of free space\""
            ),
        });
    }

    // -- File applications, ordered by partition (layout order)
    //    then destination path: deterministic on every machine.
    let mut applications: Vec<ApplyFileStep> = Vec::new();
    let mut esp_sorted: Vec<&SetFileEntry> = esp_entries.clone();
    esp_sorted.sort_by_key(|e| rel_of(e, &options.esp_root));
    for e in esp_sorted {
        applications.push(ApplyFileStep {
            partition: PartitionRole::Esp,
            set_path: e.path.clone(),
            dest_rel: rel_of(e, &options.esp_root),
            size: e.size,
            sha256: e.sha256.clone(),
        });
    }
    let mut os_sorted: Vec<&SetFileEntry> = os_entries.clone();
    os_sorted.sort_by_key(|e| rel_of(e, &options.os_root));
    for e in os_sorted {
        applications.push(ApplyFileStep {
            partition: PartitionRole::Windows,
            set_path: e.path.clone(),
            dest_rel: rel_of(e, &options.os_root),
            size: e.size,
            sha256: e.sha256.clone(),
        });
    }
    if winre_included {
        let e = winre_entry.expect("winre_included implies an entry");
        applications.push(ApplyFileStep {
            partition: PartitionRole::WinRe,
            set_path: e.path.clone(),
            dest_rel: WINRE_IMAGE_DEST_REL.to_string(),
            size: e.size,
            sha256: e.sha256.clone(),
        });
    }

    // -- Post-apply steps.
    let esp_letter = layout
        .iter()
        .find(|p| p.role == PartitionRole::Esp)
        .and_then(|p| p.drive_letter)
        .unwrap_or('S');
    let win_letter = layout
        .iter()
        .find(|p| p.role == PartitionRole::Windows)
        .and_then(|p| p.drive_letter)
        .unwrap_or('W');
    let windows_dir = format!("{win_letter}:\\Windows");
    let mut post_steps = vec![SystemRestorePostStep::Bcdboot {
        windows_dir: windows_dir.clone(),
        system_partition: format!("{esp_letter}:"),
        firmware: source_mode,
    }];
    if winre_included {
        let re_letter = layout
            .iter()
            .find(|p| p.role == PartitionRole::WinRe)
            .and_then(|p| p.drive_letter)
            .unwrap_or('R');
        post_steps.push(SystemRestorePostStep::ReagentcSetReImage {
            path: format!("{re_letter}:\\Recovery\\WindowsRE"),
            target: windows_dir.clone(),
        });
        post_steps.push(SystemRestorePostStep::ReagentcEnable);
    }
    if !protected.is_empty() {
        post_steps.push(SystemRestorePostStep::Notice {
            id: "system_restore.bitlocker_notice".to_string(),
            text: format!(
                "BitLocker was on for {} on the source PC. This restored disk is NOT encrypted. After the PC starts for the first time, turn BitLocker on again for the Windows drive so the PC is protected like it was.",
                protected.join(", ")
            ),
        });
    }
    if secure_boot_on {
        post_steps.push(SystemRestorePostStep::Notice {
            id: "system_restore.secure_boot_note".to_string(),
            text: "Secure Boot was on for the source PC, and the boot files being restored are that PC's own signed Windows boot files. If this PC's firmware refuses them at first start, check the Secure Boot settings in the firmware setup — do not leave Secure Boot off.".to_string(),
        });
    }

    let mut plan = SystemRestorePlan {
        plan_id: String::new(),
        set_id: manifest.set_id.clone(),
        target: target.clone(),
        firmware: source_mode,
        layout,
        required_min_bytes,
        os_bytes,
        esp_bytes,
        applications,
        required_boot_files: REQUIRED_ESP_BOOT_FILES
            .iter()
            .map(|s| s.to_string())
            .collect(),
        post_steps,
        warnings,
    };
    plan.plan_id = compute_plan_id(&plan)?;
    Ok(plan)
}

/// The set-relative path of an entry under its root
/// ("<root>/<rel>" → "<rel>").
fn rel_of(entry: &SetFileEntry, root: &str) -> String {
    entry
        .path
        .strip_prefix(&format!("{root}/"))
        .unwrap_or(&entry.path)
        .to_string()
}

/// Find the set's WinRE image among the OS-root files: first the
/// staged location a running Windows keeps it in
/// (`Windows\System32\Recovery\Winre.wim`), then any other
/// `Recovery\WindowsRE\Winre.wim` path (e.g. a recovery partition
/// that was captured into the OS root). Deterministic: manifest
/// order within each tier.
fn find_winre_image<'m>(
    os_entries: &[&'m SetFileEntry],
    options: &SystemRestoreOptions,
) -> Option<&'m SetFileEntry> {
    for e in os_entries {
        if rel_of(e, &options.os_root).eq_ignore_ascii_case(WINRE_STAGED_REL) {
            return Some(e);
        }
    }
    for e in os_entries {
        let lower = e.path.to_lowercase();
        if lower.ends_with("/recovery/windowsre/winre.wim") {
            return Some(e);
        }
    }
    None
}

fn compute_plan_id(plan: &SystemRestorePlan) -> Result<String> {
    let mut blanked = plan.clone();
    blanked.plan_id = String::new();
    let json =
        serde_json::to_string(&blanked).map_err(|e| CoreError::SystemRestoreInvalidFacts {
            reason: format!("plan could not be serialized for id computation: {e}"),
        })?;
    Ok(sha256_hex(json.as_bytes()))
}
