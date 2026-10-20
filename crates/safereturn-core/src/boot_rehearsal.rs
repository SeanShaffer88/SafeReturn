//! Level-3 Boot Rehearsal (S6, slice 4): prove as much of a
//! whole-PC restore as can be proven *without touching a real
//! disk* — and say plainly which part cannot.
//!
//! A Boot Rehearsal run:
//! 1. Plans the system restore with the S5 planner (same layout,
//!    same refusals — a set that cannot plan a restore cannot
//!    rehearse one).
//! 2. Applies the plan into per-partition staging directories with
//!    the S5 simulation executor (the production chunk-restore
//!    path: every file rebuilt from the encrypted set and
//!    hash-checked as it lands), leaving the same artifacts a real
//!    restore leaves (restore log, diskpart script).
//! 3. Verifies the staging tree with S5's `verify_system_restore`.
//! 4. Emits the machine-only remainder as a **guided checklist of
//!    data**: the Hyper-V steps (PowerShell commands, for editions
//!    that have Hyper-V) or the validation-only path (Windows Home:
//!    artifact checks + a guided boot test of the recovery USB
//!    itself, per the architecture plan's L3 fallback).
//!
//! The report keeps four facts separate, forever:
//! - `files_verified` — every planned file is in the staging tree
//!   with matching content (proven here, by re-reading).
//! - `layout_valid` — the plan's GPT layout is internally
//!   consistent (re-checked here from the plan data).
//! - `boot_registered` — a sourced `Fact` that is ALWAYS unknown
//!   from this code: BCD registration is created by bcdboot on a
//!   machine and proven by a boot, not by files being present.
//! - `vm_boot` — `NotBootTested` until the on-machine step records
//!   an outcome into the rehearsal record file
//!   (`record_vm_boot_outcome`). A rehearsal report states
//!   "not boot-tested" until then, in those words.
//!
//! Nothing here erases or writes any disk: the only writes are
//! inside the caller-chosen staging directory.

use crate::error::{io_at, CoreError, Result};
use crate::system::Fact;
use crate::system_restore::{PartitionRole, SystemRestorePlan};
use crate::system_restore_verify::{PartitionVerify, SystemRestoreVerifyReport};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The rehearsal record: the report of a run, written into the
/// staging directory. The on-machine VM-boot step completes it
/// later via `record_vm_boot_outcome` — the same record-file
/// protocol idea as the S4 boot-test marker.
pub const REHEARSAL_RECORD_FILE: &str = "safereturn-rehearsal.json";
pub const REHEARSAL_RECORD_FORMAT_VERSION: u32 = 1;

/// The sentence every not-yet-boot-tested report carries, verbatim.
/// It is a constant so the CLI, the shells, and the tests all assert
/// on the same words.
pub const NOT_BOOT_TESTED_LINE: &str =
    "Not boot-tested: the restored system has not been started in a virtual machine or on hardware by this rehearsal. Only the on-machine step can record a boot outcome.";

/// What the host states about VM capability. `None` at plan time
/// means "not stated" — the checklist then carries the
/// validation-only path (the conservative default: most Home PCs
/// have no Hyper-V, and claiming its steps as *the* path would
/// strand those users).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmFacts {
    pub hyperv_available: bool,
    /// Windows edition label as the host reported it (data).
    pub edition: Option<String>,
}

/// One guided step of the machine-only remainder. Commands are
/// data: SafeReturn never executes them from here; the user (or a
/// support tech) runs them on the machine and records the outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistStep {
    pub id: String,
    pub title: String,
    /// Exact command line for the step, when it has one (rendered
    /// from this run's actual plan data — sizes, paths, commands).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The VM-boot fact of a rehearsal. Only the on-machine completion
/// step may move it away from `NotBootTested`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VmBootStatus {
    NotBootTested,
    Recorded {
        recorded_unix: u64,
        /// What happened, in the operator's words (e.g. "reached
        /// the Windows logon screen in 3 minutes").
        outcome: String,
        /// Where the outcome came from (a person, a script) — a
        /// recorded outcome without a source is not a fact.
        source: String,
    },
}

/// The Boot Rehearsal plan: the S5 restore plan it will apply to
/// staging, plus the guided checklist for the machine-only steps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootRehearsalPlan {
    pub restore_plan: SystemRestorePlan,
    pub staging_dir: String,
    pub checklist: Vec<ChecklistStep>,
}

/// The report of one Boot Rehearsal run. Also the rehearsal
/// record file's content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BootRehearsalReport {
    pub format_version: u32,
    pub set_id: String,
    pub plan_id: String,
    pub rehearsed_unix: u64,
    pub staging_dir: String,
    /// Every planned file present in staging with matching
    /// content, per `verify_system_restore`. False when the
    /// application itself failed part-way (see
    /// `application_error`) — the partitions that failed are named
    /// in `partitions`.
    pub files_verified: bool,
    pub partitions: Vec<PartitionVerify>,
    /// The plan's GPT layout re-checked for internal consistency.
    pub layout_valid: bool,
    pub layout_detail: String,
    /// Always unknown from a rehearsal: see the module docs.
    pub boot_registered: Fact<bool>,
    pub vm_boot: VmBootStatus,
    /// Set when applying the set to staging failed (e.g. a damaged
    /// chunk): the rehearsal still verified what landed and names
    /// the affected partitions, rather than dying with a bare
    /// error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_error: Option<String>,
    /// Plan warning ids (strings-table), carried from the restore
    /// plan (WinRE missing, BitLocker not restored, …).
    pub warnings: Vec<String>,
    pub checklist: Vec<ChecklistStep>,
}

impl BootRehearsalReport {
    /// The one-line verdict a shell can show verbatim: what was
    /// proven, and — until a machine records otherwise — the words
    /// "Not boot-tested".
    pub fn verdict_line(&self) -> String {
        let files = if self.files_verified {
            "files verified"
        } else {
            "FILES DID NOT VERIFY"
        };
        let layout = if self.layout_valid {
            "layout valid"
        } else {
            "LAYOUT INVALID"
        };
        match &self.vm_boot {
            VmBootStatus::NotBootTested => {
                format!("Boot Rehearsal: {files}, {layout}. {NOT_BOOT_TESTED_LINE}")
            }
            VmBootStatus::Recorded { outcome, .. } => {
                format!("Boot Rehearsal: {files}, {layout}. VM boot recorded: {outcome}")
            }
        }
    }

    /// The rehearsal counts as passed when the files verify and
    /// the layout is valid. Boot outcomes are separate facts and
    /// never gate this — an untested boot is disclosed, not failed.
    pub fn passed(&self) -> bool {
        self.files_verified && self.layout_valid
    }
}

/// Re-check a plan's layout for internal consistency: partitions
/// in on-disk order, contiguous from the front reserve, no
/// overlaps, ending within the target (with the end reserve), and
/// the roles a bootable layout needs. Returns (valid, detail).
pub fn validate_layout(plan: &SystemRestorePlan) -> (bool, String) {
    use crate::system_restore::{GPT_END_RESERVE_BYTES, GPT_FRONT_RESERVE_BYTES};
    let mut problems: Vec<String> = Vec::new();
    let mut cursor = GPT_FRONT_RESERVE_BYTES;
    let mut roles: Vec<PartitionRole> = Vec::new();
    for (i, part) in plan.layout.iter().enumerate() {
        if part.index != (i + 1) as u32 {
            problems.push(format!(
                "partition {} has index {} (indexes must be 1-based and in order)",
                part.role.dir_name(),
                part.index
            ));
        }
        if part.offset_bytes != cursor {
            problems.push(format!(
                "partition {} starts at {} but the previous partition ends at {} (gap or overlap)",
                part.role.dir_name(),
                part.offset_bytes,
                cursor
            ));
        }
        if part.size_bytes == 0 {
            problems.push(format!("partition {} has size 0", part.role.dir_name()));
        }
        cursor += part.size_bytes;
        roles.push(part.role);
    }
    if cursor + GPT_END_RESERVE_BYTES > plan.target.size_bytes {
        problems.push(format!(
            "the layout ends at {cursor} bytes and the end reserve needs {GPT_END_RESERVE_BYTES} more, but the target has {} bytes",
            plan.target.size_bytes
        ));
    }
    for required in [PartitionRole::Esp, PartitionRole::Windows] {
        if !roles.contains(&required) {
            problems.push(format!(
                "the layout has no {} partition",
                required.dir_name()
            ));
        }
    }
    if problems.is_empty() {
        (
            true,
            format!(
                "{} partitions, contiguous GPT layout ending at {cursor} of {} bytes",
                plan.layout.len(),
                plan.target.size_bytes
            ),
        )
    } else {
        (false, problems.join("; "))
    }
}

/// The guided checklist for the machine-only steps, computed from
/// the actual plan. With Hyper-V: build a VHDX from the staging
/// tree, create a Generation-2 VM, boot it, record the outcome.
/// Without (the Home fallback): validate the artifacts, then the
/// guided boot test of the recovery USB itself.
pub fn vm_checklist(
    plan: &SystemRestorePlan,
    staging_dir: &Path,
    vm: Option<&VmFacts>,
) -> Vec<ChecklistStep> {
    let staging = staging_dir.display().to_string();
    let vhdx = staging_dir.join("safereturn-rehearsal.vhdx");
    let vhdx = vhdx.display().to_string();
    let size = plan.target.size_bytes;
    let mut steps: Vec<ChecklistStep> = Vec::new();
    match vm {
        Some(facts) if facts.hyperv_available => {
            steps.push(ChecklistStep {
                id: "vm.create_vhdx".to_string(),
                title: "Create the virtual disk the restored partitions will be copied into".to_string(),
                command: Some(format!(
                    "New-VHD -Path \"{vhdx}\" -SizeBytes {size} -Dynamic"
                )),
                note: Some(format!(
                    "Run in an elevated PowerShell on the host PC. The size matches the restore target the plan was made for ({} bytes).",
                    plan.target.size_bytes
                )),
            });
            steps.push(ChecklistStep {
                id: "vm.partition_vhdx".to_string(),
                title: "Partition the virtual disk exactly as the plan lays out".to_string(),
                command: Some(format!(
                    "diskpart /s \"{staging}\\safereturn-diskpart.txt\""
                )),
                note: Some(
                    "First mount the VHDX (Mount-VHD) and adjust the script's disk number to the mounted disk. The script in the staging folder was generated from this plan by the rehearsal — check its target disk line before running it.".to_string(),
                ),
            });
            for role in [
                PartitionRole::Esp,
                PartitionRole::Windows,
                PartitionRole::WinRe,
            ] {
                if plan.partition(role).is_none() {
                    continue;
                }
                let letter = plan
                    .partition(role)
                    .and_then(|p| p.drive_letter)
                    .unwrap_or('?');
                steps.push(ChecklistStep {
                    id: format!("vm.copy_{}", role.dir_name()),
                    title: format!(
                        "Copy the staged {} files onto the virtual disk's {} partition",
                        role.dir_name(),
                        role.dir_name()
                    ),
                    command: Some(format!(
                        "robocopy \"{staging}\\{}\" {letter}:\\ /E",
                        role.dir_name()
                    )),
                    note: None,
                });
            }
            for cmd in crate::system_restore_exec::post_step_commands(plan) {
                steps.push(ChecklistStep {
                    id: format!("vm.boot_step.{}", cmd[0]),
                    title: format!("Run the plan's boot step: {}", cmd.join(" ")),
                    command: Some(cmd.join(" ")),
                    note: Some(
                        "Run against the mounted virtual disk (its drive letters are the ones in the command). This is the step whose result makes boot registration a known fact — on the machine, not here.".to_string(),
                    ),
                });
            }
            steps.push(ChecklistStep {
                id: "vm.create_vm".to_string(),
                title: "Create the Generation-2 (UEFI) test VM and attach the disk".to_string(),
                command: Some(format!(
                    "New-VM -Name \"SafeReturn-Rehearsal\" -Generation 2 -MemoryStartupBytes 4GB -VHDPath \"{vhdx}\""
                )),
                note: None,
            });
            steps.push(ChecklistStep {
                id: "vm.boot_vm".to_string(),
                title: "Start the VM and watch for the Windows logon screen".to_string(),
                command: Some(
                    "Start-VM -Name \"SafeReturn-Rehearsal\"; VMConnect localhost \"SafeReturn-Rehearsal\"".to_string(),
                ),
                note: Some(
                    "Record what you see: logon screen reached (and roughly how long it took), or the exact error on screen.".to_string(),
                ),
            });
        }
        _ => {
            steps.push(ChecklistStep {
                id: "home.check_artifacts".to_string(),
                title: "Check the rehearsal artifacts in the staging folder".to_string(),
                command: None,
                note: Some(format!(
                    "This PC has no Hyper-V available{}, so the VM boot cannot run here. In {staging} you should find safereturn-diskpart.txt (the exact partitioning script) and safereturn-restore-log.json (what was applied). Their presence was checked by the rehearsal; the restore itself was fully verified above.",
                    match vm.and_then(|f| f.edition.as_ref()) {
                        Some(ed) => format!(" (edition reported: {ed})"),
                        None => String::new(),
                    }
                )),
            });
            steps.push(ChecklistStep {
                id: "home.boot_usb".to_string(),
                title: "Boot-test the recovery USB on this PC".to_string(),
                command: None,
                note: Some(
                    "Restart the PC, open its boot menu, and choose the SafeReturn recovery USB. If the recovery shell opens, the media is boot-tested on this PC — the shell records that boot on the media automatically (the S4 boot-test marker). This tests the media, not the restored Windows: the restored system itself remains not boot-tested until it is booted, which only a real restore (or Hyper-V) can do.".to_string(),
                ),
            });
        }
    }
    steps.push(ChecklistStep {
        id: "record.outcome".to_string(),
        title: "Record the boot outcome in the rehearsal record".to_string(),
        command: Some(format!(
            "safereturn rehearse-boot report \"{staging}\" --record-vm-boot \"<what happened>\" --source \"<who or what observed it>\""
        )),
        note: Some(
            "Until this is done, the rehearsal report keeps saying \"not boot-tested\" — that wording is deliberate.".to_string(),
        ),
    });
    steps
}

/// Build the report for a finished application + verification.
/// Pure assembly: the engine's run (and the tests) share it.
pub fn assemble_report(
    plan: &SystemRestorePlan,
    staging_dir: &Path,
    verify: &SystemRestoreVerifyReport,
    application_error: Option<String>,
    vm: Option<&VmFacts>,
    rehearsed_unix: u64,
) -> BootRehearsalReport {
    let (layout_valid, layout_detail) = validate_layout(plan);
    BootRehearsalReport {
        format_version: REHEARSAL_RECORD_FORMAT_VERSION,
        set_id: plan.set_id.clone(),
        plan_id: plan.plan_id.clone(),
        rehearsed_unix,
        staging_dir: staging_dir.display().to_string(),
        files_verified: application_error.is_none() && verify.files_in_place(),
        partitions: verify.partitions.clone(),
        layout_valid,
        layout_detail,
        boot_registered: Fact::unknown(
            "boot rehearsal (file inspection of the staging tree)",
            "boot registration is created by bcdboot/reagentc on a machine and proven by a boot. A rehearsal applies files to a staging folder; the checklist's on-machine steps are where registration happens and is observed.",
        ),
        vm_boot: VmBootStatus::NotBootTested,
        application_error,
        warnings: plan.warnings.iter().map(|w| w.id().to_string()).collect(),
        checklist: vm_checklist(plan, staging_dir, vm),
    }
}

/// Write the rehearsal record (the report) into the staging
/// directory, atomically (temp file + rename, the repo's rule).
pub fn write_rehearsal_record(staging_dir: &Path, report: &BootRehearsalReport) -> Result<()> {
    std::fs::create_dir_all(staging_dir).map_err(|e| io_at(&staging_dir.to_path_buf(), e))?;
    let path = staging_dir.join(REHEARSAL_RECORD_FILE);
    let json = serde_json::to_string_pretty(report).map_err(|e| CoreError::Json {
        path: path.clone(),
        source: e,
    })?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json).map_err(|e| io_at(&tmp, e))?;
    std::fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
    Ok(())
}

/// Read a rehearsal record back. A missing record is a typed
/// "not a rehearsal staging folder" error; a malformed one is
/// invalid data — never a fresh-looking report.
pub fn read_rehearsal_record(staging_dir: &Path) -> Result<BootRehearsalReport> {
    let path = staging_dir.join(REHEARSAL_RECORD_FILE);
    if !path.exists() {
        return Err(CoreError::MediaManifestMissing {
            path: staging_dir.to_path_buf(),
        });
    }
    let text = std::fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    let report: BootRehearsalReport =
        serde_json::from_str(&text).map_err(|e| CoreError::MediaManifestInvalid {
            reason: format!("{REHEARSAL_RECORD_FILE} is not valid SafeReturn data: {e}"),
        })?;
    if report.format_version != REHEARSAL_RECORD_FORMAT_VERSION {
        return Err(CoreError::MediaManifestInvalid {
            reason: format!(
                "rehearsal record format {} is not supported by this version (expected {})",
                report.format_version, REHEARSAL_RECORD_FORMAT_VERSION
            ),
        });
    }
    Ok(report)
}

/// The on-machine completion step: record a VM-boot outcome into
/// an existing rehearsal record. This is the ONLY way `vm_boot`
/// leaves `NotBootTested`, and it requires a stated source — a
/// boot claim without provenance is not recorded.
pub fn record_vm_boot_outcome(
    staging_dir: &Path,
    outcome: &str,
    source: &str,
    recorded_unix: u64,
) -> Result<BootRehearsalReport> {
    if outcome.trim().is_empty() || source.trim().is_empty() {
        return Err(CoreError::SystemRestoreInvalidFacts {
            reason: "a VM boot outcome needs both what happened and its source (who or what observed it) — an unsourced boot claim is not recorded".to_string(),
        });
    }
    let mut report = read_rehearsal_record(staging_dir)?;
    report.vm_boot = VmBootStatus::Recorded {
        recorded_unix,
        outcome: outcome.to_string(),
        source: source.to_string(),
    };
    write_rehearsal_record(staging_dir, &report)?;
    Ok(report)
}
