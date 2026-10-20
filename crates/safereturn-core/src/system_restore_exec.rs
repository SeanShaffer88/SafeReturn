//! System-restore execution (S5, slice 2): the executor trait
//! behind the engine's plan-token flow, a **simulation executor**
//! that applies a plan to a directory-backed fake disk (the
//! documented test path — the full flow, from a real encrypted set,
//! on any OS), the pure generators for the exact diskpart script
//! and boot command lines a real restore would run, and the
//! Windows disk executor skeleton (compile-verified, env-gated,
//! renders its artifacts and refuses to run them — running them is
//! the on-machine session in docs/S5_NOTES.md).
//!
//! Honesty rules enforced here:
//! - The simulation NEVER claims a post-apply command ran. bcdboot /
//!   reagentc steps are recorded in the restore log with status
//!   `recorded_simulated`; only the on-machine flow may ever record
//!   a command as executed. Verification keeps "files in place" and
//!   "boot registered" as separate facts for the same reason.
//! - The diskpart script is generated from the plan as data and
//!   unit-tested byte-for-byte: a wrong script is the scariest
//!   failure mode in this feature, so it is treated as code, not
//!   as a string someone typed at a console.
//! - A live restore never starts from an ambient call: the Windows
//!   executor requires SR_RESTORE_LIVE=1 before it even renders.

use crate::error::{io_at, CoreError, Result};
use crate::sets::{read_set_manifest, restore_entries};
use crate::system_restore::{
    PartitionFilesystem, PartitionRole, SystemRestorePlan, SystemRestoreTargetFacts,
    SystemRestoreWarning,
};
use crate::volume::UnlockedVolume;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

/// Environment switch that permits the Windows executor to be
/// constructed for a live run. Rendering artifacts (the skeleton's
/// current behavior) also sits behind it — nothing about a real
/// disk happens from an ambient call.
pub const RESTORE_LIVE_ENV: &str = "SR_RESTORE_LIVE";

/// File the executors leave at the root of an applied (real or
/// simulated) disk: which plan ran, what it warned about, and what
/// happened to each post-apply step.
pub const RESTORE_LOG_FILE: &str = "safereturn-restore-log.json";
pub const RESTORE_LOG_FORMAT_VERSION: u32 = 1;
/// File the simulation and the Windows skeleton leave next to the
/// log: the exact diskpart script this plan would run on a real
/// disk, kept for inspection.
pub const DISKPART_SCRIPT_FILE: &str = "safereturn-diskpart.txt";

/// What an executor reports back to the engine after a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRestoreExecution {
    /// True for the directory-backed simulation. The engine reports
    /// simulated and real runs under different summary ids — a
    /// simulation must never read as a completed real restore.
    pub simulated: bool,
    /// Root of the applied disk (the simulation directory; on a real
    /// run, wherever the executor staged its record). Verification
    /// runs against this root.
    pub applied_root: Option<PathBuf>,
    pub files_written: u64,
    pub bytes_written: u64,
    pub post_steps_recorded: usize,
}

/// Executes one confirmed system-restore plan. Implementations are
/// chosen by the caller (engine flow in `engine.rs`); the engine
/// has already consumed the plan token and re-checked the target
/// facts before `execute` is ever called.
pub trait SystemRestoreExecutor {
    fn execute(
        &self,
        volume: &UnlockedVolume,
        plan: &SystemRestorePlan,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<SystemRestoreExecution>;
}

/// One recorded post-apply step in the restore log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPostStep {
    pub description: String,
    /// Exact argv for command steps; absent for notices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// "recorded_simulated" (simulation — the command did NOT run),
    /// "executed" / "failed" (on-machine flow only). No other values
    /// are produced by this build.
    pub status: String,
}

/// The restore log written to an applied disk's root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreLog {
    pub format_version: u32,
    pub plan_id: String,
    pub set_id: String,
    pub simulated: bool,
    pub applied_unix: u64,
    pub target: SystemRestoreTargetFacts,
    pub warnings: Vec<SystemRestoreWarning>,
    pub post_steps: Vec<RecordedPostStep>,
}

impl RestoreLog {
    fn for_plan(plan: &SystemRestorePlan, simulated: bool, status: &str) -> Self {
        Self {
            format_version: RESTORE_LOG_FORMAT_VERSION,
            plan_id: plan.plan_id.clone(),
            set_id: plan.set_id.clone(),
            simulated,
            applied_unix: crate::engine::now_unix(),
            target: plan.target.clone(),
            warnings: plan.warnings.clone(),
            post_steps: plan
                .post_steps
                .iter()
                .map(|s| RecordedPostStep {
                    description: s.describe(),
                    command: s.command(),
                    status: status.to_string(),
                })
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Pure generators: the diskpart script and the boot command lines.
// These are the highest-value verification available without a
// machine, and they are tested byte-for-byte.

const MIB: u64 = 1024 * 1024;

/// The DiskPart script that lays out `plan` on disk `disk_index`,
/// following Microsoft Learn's documented UEFI/GPT sample scripts
/// ("Sample: Configure UEFI/GPT-Based Hard Drive Partitions by Using
/// Windows PE and DiskPart"; the Windows RE partition's type id and
/// GPT attributes are also those of Microsoft Support KB 5028997):
/// `create partition efi/msr/primary` with explicit MiB sizes,
/// FAT32 "System" / NTFS "Windows" / NTFS "Windows RE tools",
/// letters S/W/R as in the samples. All plan partition sizes are
/// 1 MiB-aligned except the Windows partition on a target whose
/// size is not a whole MiB — there the script floors to whole MiB
/// and the sub-MiB remainder stays unallocated (the plan's end
/// reserve already accounts for the backup GPT).
pub fn diskpart_script(plan: &SystemRestorePlan, disk_index: u32) -> String {
    let t = &plan.target;
    let mut s = String::new();
    s.push_str(&format!(
        "rem SafeReturn system restore - plan {}\n",
        plan.plan_id
    ));
    s.push_str(&format!(
        "rem Target disk {disk_index}: {} (serial ...{}), {} bytes\n",
        t.model, t.serial_suffix, t.size_bytes
    ));
    s.push_str(&format!(
        "rem WARNING: this script ERASES disk {disk_index} completely.\n"
    ));
    s.push_str(&format!("select disk {disk_index}\n"));
    s.push_str("clean\n");
    s.push_str("convert gpt\n");
    for part in &plan.layout {
        let mib = part.size_bytes / MIB;
        s.push_str(&format!(
            "rem Partition {}: {} - {} MiB{}\n",
            part.index,
            role_name(part.role),
            mib,
            match part.filesystem {
                Some(PartitionFilesystem::Fat32) => ", FAT32",
                Some(PartitionFilesystem::Ntfs) => ", NTFS",
                None => "",
            }
        ));
        match part.role {
            PartitionRole::Esp => s.push_str(&format!("create partition efi size={mib}\n")),
            PartitionRole::Msr => s.push_str(&format!("create partition msr size={mib}\n")),
            PartitionRole::Windows | PartitionRole::WinRe => {
                s.push_str(&format!("create partition primary size={mib}\n"))
            }
        }
        match part.filesystem {
            Some(fs_kind) => {
                let fs_name = match fs_kind {
                    PartitionFilesystem::Fat32 => "fat32",
                    PartitionFilesystem::Ntfs => "ntfs",
                };
                s.push_str(&format!(
                    "format quick fs={fs_name} label=\"{}\"\n",
                    part.label.as_deref().unwrap_or("")
                ));
            }
            None => {}
        }
        if let Some(letter) = part.drive_letter {
            s.push_str(&format!("assign letter=\"{letter}\"\n"));
        }
        if part.role == PartitionRole::WinRe {
            s.push_str(&format!("set id=\"{}\"\n", part.type_guid.to_lowercase()));
            if let Some(attrs) = &part.gpt_attributes {
                s.push_str(&format!("gpt attributes={attrs}\n"));
            }
        }
    }
    s.push_str("list volume\n");
    s.push_str("exit\n");
    s
}

fn role_name(role: PartitionRole) -> &'static str {
    match role {
        PartitionRole::Esp => "EFI System Partition (ESP)",
        PartitionRole::Msr => "Microsoft Reserved (MSR)",
        PartitionRole::Windows => "Windows",
        PartitionRole::WinRe => "Windows RE tools",
    }
}

/// The exact command lines the post-apply phase runs on a real
/// disk, in order (bcdboot, then reagentc /setreimage, then
/// reagentc /enable). Notices are not commands and are absent here.
pub fn post_step_commands(plan: &SystemRestorePlan) -> Vec<Vec<String>> {
    plan.post_steps.iter().filter_map(|s| s.command()).collect()
}

/// Join a plan destination ('/'-separated, partition-relative) onto
/// a base directory, component by component — never by string
/// concatenation, so the result is a valid path on any OS.
pub fn dest_path(base: &PathBuf, dest_rel: &str) -> PathBuf {
    let mut out = base.clone();
    for part in dest_rel.split('/') {
        out.push(part);
    }
    out
}

// ---------------------------------------------------------------------------
// Simulation executor: the full flow against a directory-backed
// fake disk. Partition directories are named by PartitionRole::
// dir_name ("esp", "msr", "windows", "winre"). Files are applied
// through the same chunk-rebuilding, hash-verifying restore path
// file restores use; the plan's warnings ride into the restore log;
// post-apply commands are recorded, never run.

pub struct SimulatedDiskExecutor {
    /// Root of the fake disk (created if needed).
    pub root: PathBuf,
}

impl SystemRestoreExecutor for SimulatedDiskExecutor {
    fn execute(
        &self,
        volume: &UnlockedVolume,
        plan: &SystemRestorePlan,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<SystemRestoreExecution> {
        let manifest = read_set_manifest(volume, &plan.set_id)?;
        for spec in &plan.layout {
            let dir = self.root.join(spec.role.dir_name());
            fs::create_dir_all(&dir).map_err(|e| io_at(&dir, e))?;
        }
        let mut entries: Vec<(crate::sets::SetFileEntry, PathBuf)> =
            Vec::with_capacity(plan.applications.len());
        for step in &plan.applications {
            let entry = manifest
                .file(&step.set_path)
                .ok_or_else(|| CoreError::FileNotInSet {
                    set_id: plan.set_id.clone(),
                    path: step.set_path.clone(),
                })?
                .clone();
            let dest = dest_path(&self.root.join(step.partition.dir_name()), &step.dest_rel);
            entries.push((entry, dest));
        }
        // The fake disk starts blank; identical files already there
        // (a re-run over the same directory) are counted, different
        // content is a RestoreConflict — the same honesty rules as a
        // file restore, by construction (same code path).
        let outcome = restore_entries(volume, &entries, &HashSet::new(), progress)?;

        // Record — never run — the post-apply steps, and keep the
        // exact diskpart script beside the log for inspection.
        let log = RestoreLog::for_plan(plan, true, "recorded_simulated");
        write_restore_artifacts(&self.root, plan, &log)?;

        Ok(SystemRestoreExecution {
            simulated: true,
            applied_root: Some(self.root.clone()),
            files_written: outcome.files_written as u64,
            bytes_written: outcome.bytes_written,
            post_steps_recorded: log.post_steps.len(),
        })
    }
}

fn write_restore_artifacts(
    root: &PathBuf,
    plan: &SystemRestorePlan,
    log: &RestoreLog,
) -> Result<()> {
    fs::create_dir_all(root).map_err(|e| io_at(root, e))?;
    let log_path = root.join(RESTORE_LOG_FILE);
    let json = serde_json::to_string_pretty(log).map_err(|e| CoreError::Json {
        path: log_path.clone(),
        source: e,
    })?;
    let tmp = log_path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| io_at(&tmp, e))?;
    fs::rename(&tmp, &log_path).map_err(|e| io_at(&log_path, e))?;
    let script_path = root.join(DISKPART_SCRIPT_FILE);
    fs::write(&script_path, diskpart_script(plan, 0)).map_err(|e| io_at(&script_path, e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Real-disk executors.

/// The executor shells get off Windows: executing a bare-metal
/// restore on a real disk is Windows work, and saying so with the
/// established typed error is the contract.
pub struct UnsupportedSystemRestoreExecutor;

impl SystemRestoreExecutor for UnsupportedSystemRestoreExecutor {
    fn execute(
        &self,
        _volume: &UnlockedVolume,
        _plan: &SystemRestorePlan,
        _progress: &mut dyn FnMut(u64, u64),
    ) -> Result<SystemRestoreExecution> {
        Err(CoreError::UnsupportedPlatform {
            feature: "executing a bare-metal restore on a real disk",
        })
    }
}

/// Pick the real-disk executor for this platform. On Windows that
/// is the (gated, skeleton) disk executor for `disk_index`, writing
/// its rendered artifacts under `work_dir`; elsewhere the
/// unsupported executor. The simulation executor is never returned
/// here — simulation is always an explicit caller choice.
#[cfg(windows)]
pub fn platform_system_restore_executor(
    disk_index: u32,
    work_dir: PathBuf,
) -> Box<dyn SystemRestoreExecutor> {
    Box::new(WindowsDiskExecutor {
        disk_index,
        work_dir,
    })
}

#[cfg(not(windows))]
pub fn platform_system_restore_executor(
    _disk_index: u32,
    _work_dir: PathBuf,
) -> Box<dyn SystemRestoreExecutor> {
    Box::new(UnsupportedSystemRestoreExecutor)
}

/// Windows real-disk executor — SKELETON (S5). Env-gated like the
/// media executor (SR_RESTORE_LIVE=1). When the gate is satisfied
/// it renders the plan's exact diskpart script and boot command
/// lines into `work_dir` (the same artifacts the simulation leaves,
/// with the real disk index), then refuses with
/// SystemRestoreExecutorNotReady: partitioning a real disk, applying
/// files to raw volumes, and running bcdboot/reagentc against them
/// is the on-machine S5 session (docs/S5_NOTES.md) and has never
/// been run. A skeleton that cannot erase anything is the honest
/// state of this code today.
#[cfg(windows)]
pub struct WindowsDiskExecutor {
    pub disk_index: u32,
    pub work_dir: PathBuf,
}

#[cfg(windows)]
impl SystemRestoreExecutor for WindowsDiskExecutor {
    fn execute(
        &self,
        _volume: &UnlockedVolume,
        plan: &SystemRestorePlan,
        _progress: &mut dyn FnMut(u64, u64),
    ) -> Result<SystemRestoreExecution> {
        if std::env::var(RESTORE_LIVE_ENV).ok().as_deref() != Some("1") {
            return Err(CoreError::SystemRestoreLiveNotEnabled {
                env_var: RESTORE_LIVE_ENV,
            });
        }
        fs::create_dir_all(&self.work_dir).map_err(|e| io_at(&self.work_dir, e))?;
        let script_path = self.work_dir.join(DISKPART_SCRIPT_FILE);
        fs::write(&script_path, diskpart_script(plan, self.disk_index))
            .map_err(|e| io_at(&script_path, e))?;
        let commands_path = self.work_dir.join("safereturn-restore-commands.json");
        let commands = post_step_commands(plan);
        let json = serde_json::to_string_pretty(&commands).map_err(|e| CoreError::Json {
            path: commands_path.clone(),
            source: e,
        })?;
        fs::write(&commands_path, json).map_err(|e| io_at(&commands_path, e))?;
        Err(CoreError::SystemRestoreExecutorNotReady {
            detail: format!(
                "the diskpart script and boot command lines this plan would run were written to {} for inspection, but this build does not run them against a real disk — partitioning, applying files to raw volumes, and running bcdboot/reagentc are verified in the on-machine restore session first (docs/S5_NOTES.md)",
                self.work_dir.display()
            ),
        })
    }
}
