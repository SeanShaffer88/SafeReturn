//! The engine API: the operations shells can ask for, shaped by the
//! shell contract (`safereturn-contract` types, docs/SHELL_CONTRACT.md).
//!
//! Rules implemented here, because the contract assigns them to the
//! engine and no shell may be trusted to enforce them:
//!
//! - Every long operation is a *job*: JobStarted → JobProgress* →
//!   JobFinished, in that order, via the caller's event sink.
//! - Restores only happen through a **plan**: `plan_restore` shows
//!   exactly what would be written and which existing files would be
//!   replaced, and returns a single-use token. `start_restore` requires
//!   that exact token, consumes it, and — before the job starts —
//!   re-checks each target's presence and content hash. A changed target
//!   makes the plan stale before any restore writes. Targets are checked
//!   again during the job; a later change stops further writes, but earlier
//!   files may already have been restored. These checks are not race-free.
//!   There is no other restore entry point in this API, so "execute without
//!   a token" is an unknown-token error.
//! - Media creation follows the same plan discipline (S4):
//!   `plan_media` computes the layout and returns a token;
//!   `create_media` consumes it, re-checks the target facts (size,
//!   removable, serial suffix) against the plan, and only then hands
//!   the plan to a `MediaExecutor`. Drift refuses with nothing
//!   written — the device that would be erased must be the device
//!   the user confirmed.
//! - Whole-PC restore follows the same discipline a third time (S5):
//!   `plan_system_restore` computes the GPT layout and returns a
//!   token; `execute_system_restore` consumes it, re-checks the
//!   target facts (size, removable, serial suffix, firmware mode),
//!   and only then hands the plan to a `SystemRestoreExecutor`
//!   (simulation, Windows skeleton, or unsupported). A simulated
//!   run finishes under a different summary id than a real one —
//!   the two are never conflated.
//! - Level-2 File Rehearsal restores chosen files plus a deterministic
//!   pseudo-random sample into a temporary sandbox and compares hashes;
//!   the sample is reproducible (seeded from the set id), so a rehearsal
//!   result can be re-run and compared.

use crate::boot_rehearsal::{
    assemble_report, vm_checklist, write_new_rehearsal_record, BootRehearsalPlan,
    BootRehearsalReport, VmFacts, REHEARSAL_RECORD_FILE,
};
use crate::capture::{CaptureSource, LiveSource};
use crate::error::{CoreError, Result};
use crate::media::{
    plan_media_checked as compute_media_plan_checked, MediaFacts, MediaPlan as CoreMediaPlan,
    MediaPlanOptions, MediaTargetFacts,
};
use crate::media_exec::{MediaExecutor, MEDIA_CREATION_UNAVAILABLE_WARNING_ID};
use crate::restore_safety::{inspect_directory, join_relative, require_absent_file};
use crate::safe_target::{
    assess_media_target, assess_system_restore_target, SafeTargetAssessment, SafeTargetContext,
};
use crate::sets::{
    backup_tree_with_source_progress, hash_existing_file, list_sets, read_set_manifest,
    restore_entries, restore_entries_with_snapshots, validate_restore_manifest, verify_set,
    BackupOutcome, BackupPhase, RestoreOutcome, SetFileEntry, SetManifest, SetVerifyReport,
};
use crate::system_restore::{
    plan_system_restore_checked as compute_system_restore_plan_checked, SystemRestoreOptions,
    SystemRestorePlan as CoreSystemRestorePlan, SystemRestoreTargetFacts,
};
use crate::system_restore_exec::{
    SimulatedDiskExecutor, SystemRestoreExecution, SystemRestoreExecutor, DISKPART_SCRIPT_FILE,
    RESTORE_LOG_FILE,
};
use crate::system_restore_verify::verify_system_restore;
use crate::volume::UnlockedVolume;
use safereturn_contract::{
    BackupSummary, Event, JobOutcome, MediaPlan as ContractMediaPlan, RestorePlan,
    SystemRestorePlan as ContractSystemRestorePlan,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// A saved backup with omissions must not be rendered as complete coverage.
pub const BACKUP_WITH_SKIPS_SUMMARY_ID: &str = "result.backup_succeeded_with_skips";
pub const BACKUP_WITH_SKIPS_MESSAGE: &str =
    "The backup was saved, but some items were not backed up. Review the skipped list before relying on this backup.";

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Compact byte count for plan summaries, e.g. "4.2 GB", "812 KB".
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

struct PlanState {
    /// Scope: (file entry, exact destination) pairs.
    entries: Vec<(SetFileEntry, PathBuf)>,
    /// Exact target content hash (or absence) at plan time — staleness reference.
    states: BTreeMap<String, Option<String>>,
    /// Set paths whose plan-time content differed (approved overwrites).
    overwrites: HashSet<String>,
}

/// A media plan awaiting CreateMedia: the computed plan plus the
/// target facts as they were when the user saw the plan — the
/// staleness reference. (Media plans are separate from restore plans:
/// different token namespace, different drift meaning.)
struct MediaPlanState {
    plan: CoreMediaPlan,
    target: MediaTargetFacts,
}

/// A system-restore plan awaiting StartSystemRestore: the computed
/// plan plus the target facts as they were when the user saw the
/// plan — the staleness reference. (Its own token namespace, like
/// media's: a system-restore token never restores files or creates
/// media, and vice versa.)
struct SystemRestorePlanState {
    plan: CoreSystemRestorePlan,
    target: SystemRestoreTargetFacts,
}

pub struct Engine {
    volume: UnlockedVolume,
    job_counter: u64,
    plans: HashMap<String, PlanState>,
    media_plans: HashMap<String, MediaPlanState>,
    system_restore_plans: HashMap<String, SystemRestorePlanState>,
}

impl Engine {
    pub fn new(volume: UnlockedVolume) -> Self {
        Self {
            volume,
            job_counter: 0,
            plans: HashMap::new(),
            media_plans: HashMap::new(),
            system_restore_plans: HashMap::new(),
        }
    }

    pub fn volume(&self) -> &UnlockedVolume {
        &self.volume
    }

    pub fn into_volume(self) -> UnlockedVolume {
        self.volume
    }

    fn next_job_id(&mut self) -> String {
        self.job_counter += 1;
        format!("job-{}", self.job_counter)
    }

    // -- Discovery ------------------------------------------------------

    /// Emit BackupList from the set manifests (facts only).
    pub fn list_backups(&self, sink: &mut dyn FnMut(Event)) -> Result<Vec<BackupSummary>> {
        let backups: Vec<BackupSummary> = list_sets(&self.volume)?
            .into_iter()
            .map(|s| BackupSummary {
                backup_id: s.set_id,
                label: s.label,
                created_unix: s.created_unix,
                file_count: s.files,
                total_bytes: s.bytes,
            })
            .collect();
        sink(Event::BackupList {
            backups: backups.clone(),
        });
        Ok(backups)
    }

    // -- Backup ---------------------------------------------------------

    /// StartBackup job: back up `roots` as a new set labelled `label`,
    /// reading from the live filesystem. On failure a
    /// JobFinished(Failed) event is emitted and the error is returned
    /// (the CLI/shell renders the error itself).
    pub fn start_backup(
        &mut self,
        label: &str,
        roots: &[PathBuf],
        sink: &mut dyn FnMut(Event),
    ) -> Result<BackupOutcome> {
        self.start_backup_with_source(label, roots, &LiveSource, sink)
    }

    /// StartBackup job reading through a capture source (S3) — e.g. a
    /// `MappedSource` over a VSS snapshot's device root. `roots` are
    /// logical paths; the source resolves what to open, and the set
    /// manifest records the source's capture mode. The snapshot's life
    /// cycle (begin/finish/abort) belongs to the caller: this method
    /// only reads while the caller's session is alive. A saved outcome
    /// with `manifest.skipped` is incomplete and must not be reported
    /// to snapshot writers as a completed backup. Even an empty skipped
    /// list does not prove writer-component or source completeness.
    pub fn start_backup_with_source(
        &mut self,
        label: &str,
        roots: &[PathBuf],
        source: &dyn CaptureSource,
        sink: &mut dyn FnMut(Event),
    ) -> Result<BackupOutcome> {
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let volume = &self.volume;
        let mut progress = |phase: BackupPhase, done: u64, total: u64| {
            let (phase_id, unit) = match phase {
                BackupPhase::Copying => ("phase.copying_files", "files"),
                BackupPhase::Verifying => ("phase.checking_backup", "chunk references"),
            };
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: phase_id.to_string(),
                done,
                total,
                unit: unit.to_string(),
            });
        };
        match backup_tree_with_source_progress(
            volume,
            source,
            label,
            roots,
            now_unix(),
            &mut progress,
        ) {
            Ok(outcome) => {
                // The catalog is a rebuildable cache over the manifests;
                // refresh it, but its failure must not misreport a backup
                // that did succeed — manifests remain the source of truth.
                let _ = crate::sets::rebuild_catalog(volume);
                let summary_id = if outcome.manifest.skipped.is_empty() {
                    "result.backup_succeeded"
                } else {
                    BACKUP_WITH_SKIPS_SUMMARY_ID
                };
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Succeeded,
                    summary_id: summary_id.to_string(),
                });
                Ok(outcome)
            }
            Err(e) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.backup_failed".to_string(),
                });
                Err(e)
            }
        }
    }

    // -- Level-1 verify ---------------------------------------------------

    /// StartVerify job (Rehearsal Level 1, the Quick Check).
    pub fn start_verify(
        &mut self,
        set_id: &str,
        sink: &mut dyn FnMut(Event),
    ) -> Result<SetVerifyReport> {
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let volume = &self.volume;
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.checking_backup".to_string(),
                done,
                total,
                unit: "chunk references".to_string(),
            });
        };
        match verify_set(volume, set_id, &mut progress) {
            Ok(report) => {
                let (outcome, summary) = if report.passed() {
                    (JobOutcome::Succeeded, "result.quick_check_passed")
                } else {
                    (JobOutcome::Failed, "result.quick_check_failed")
                };
                sink(Event::JobFinished {
                    job_id,
                    outcome,
                    summary_id: summary.to_string(),
                });
                Ok(report)
            }
            Err(e) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.quick_check_failed".to_string(),
                });
                Err(e)
            }
        }
    }

    // -- Restore planning + execution ------------------------------------

    /// PlanRestore: compute exactly what a restore would do. Writes
    /// nothing. `only_path: Some(p)` restricts the plan to the single
    /// file `p`, restored into `target_dir` under its file name.
    pub fn plan_restore(
        &mut self,
        backup_id: &str,
        target_dir: &std::path::Path,
        only_path: Option<&str>,
        sink: &mut dyn FnMut(Event),
    ) -> Result<RestorePlan> {
        let manifest = read_set_manifest(&self.volume, backup_id)?;
        validate_restore_manifest(&manifest)?;
        let entries = plan_entries(&manifest, target_dir, only_path, backup_id)?;
        let states = states_for_entries(&entries)?;
        let overwrites: HashSet<String> = entries
            .iter()
            .filter(|(entry, _)| {
                matches!(states.get(&entry.path), Some(Some(hash)) if hash != &entry.sha256)
            })
            .map(|(entry, _)| entry.path.clone())
            .collect();
        let overwrite_count = overwrites.len() as u64;
        let file_count = entries.len() as u64;
        let total_bytes: u64 = entries.iter().map(|(f, _)| f.size).sum();
        let token = new_plan_token()?;
        let target_summary = {
            let base = format!(
                "{} file{} ({}) to {}",
                file_count,
                if file_count == 1 { "" } else { "s" },
                format_bytes(total_bytes),
                target_dir.display()
            );
            if overwrite_count > 0 {
                format!(
                    "{base} — {overwrite_count} existing file{} will be replaced",
                    if overwrite_count == 1 { "" } else { "s" }
                )
            } else {
                base
            }
        };
        let plan = RestorePlan {
            plan_token: token.clone(),
            backup_id: backup_id.to_string(),
            target_summary,
            erase_warning_id: (overwrite_count > 0)
                .then(|| "restore.will_overwrite_files".to_string()),
            file_count,
            total_bytes,
            overwrite_count,
        };
        self.plans.insert(
            token,
            PlanState {
                entries,
                states,
                overwrites,
            },
        );
        sink(Event::RestorePlanned(plan.clone()));
        Ok(plan)
    }

    /// StartRestore: execute the plan bound to `plan_token`. The token is
    /// consumed either way. Before writing, every scoped file's target
    /// state is re-checked against the plan; any drift refuses the whole
    /// restore with PlanStale and nothing written.
    pub fn start_restore(
        &mut self,
        plan_token: &str,
        sink: &mut dyn FnMut(Event),
    ) -> Result<RestoreOutcome> {
        let plan = self
            .plans
            .remove(plan_token)
            .ok_or(CoreError::InvalidPlanToken)?;
        // Staleness re-check — the plan must still describe reality.
        let current = states_for_entries(&plan.entries)?;
        for (path, planned) in &plan.states {
            match current.get(path) {
                Some(now) if now == planned => {}
                Some(_) => {
                    return Err(CoreError::PlanStale {
                        detail: format!("the content or presence of {path} changed"),
                    })
                }
                None => {
                    return Err(CoreError::PlanStale {
                        detail: format!("{path} is no longer part of the plan scope"),
                    })
                }
            }
        }
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let volume = &self.volume;
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.restoring_files".to_string(),
                done,
                total,
                unit: "files".to_string(),
            });
        };
        match restore_entries_with_snapshots(
            volume,
            &plan.entries,
            &plan.overwrites,
            &plan.states,
            &mut progress,
        ) {
            Ok(outcome) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Succeeded,
                    summary_id: "result.restore_succeeded".to_string(),
                });
                Ok(outcome)
            }
            Err(e) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.restore_failed".to_string(),
                });
                Err(e)
            }
        }
    }

    /// Forget all outstanding plans (e.g. the shell navigated away).
    pub fn clear_plans(&mut self) {
        self.plans.clear();
        self.media_plans.clear();
        self.system_restore_plans.clear();
    }

    // -- Recovery media (S4) ----------------------------------------------

    /// PlanMedia: compute the media plan for the target the facts
    /// describe. Erases nothing; refusals from planning (too small,
    /// non-removable without override, missing WinPE source) surface
    /// as their named errors. On success, emits MediaPlanned with a
    /// single-use token bound to this exact plan.
    ///
    /// This entry point takes no SafeTarget context: no identity
    /// checks are performed. Shells that enumerated real disks use
    /// `plan_media_guarded`.
    pub fn plan_media(
        &mut self,
        facts: &MediaFacts,
        options: &MediaPlanOptions,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractMediaPlan> {
        self.plan_media_inner(facts, options, &SafeTargetAssessment::no_context(), sink)
    }

    /// PlanMedia with SafeTarget enforcement (S6): the target is
    /// checked against the context's protected disks (source /
    /// backup / running media) and its own system-disk flag before
    /// planning. A refusal or an unacknowledged warning is a typed
    /// error and NO plan token is created; acknowledged warnings are
    /// recorded in the plan. This is the entry point shells use —
    /// enforcement lives here in the engine, not in shell advice.
    pub fn plan_media_guarded(
        &mut self,
        facts: &MediaFacts,
        options: &MediaPlanOptions,
        context: &SafeTargetContext,
        target_is_system_disk: bool,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractMediaPlan> {
        let assessment = assess_media_target(&facts.target, target_is_system_disk, context);
        self.plan_media_inner(facts, options, &assessment, sink)
    }

    fn plan_media_inner(
        &mut self,
        facts: &MediaFacts,
        options: &MediaPlanOptions,
        assessment: &SafeTargetAssessment,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractMediaPlan> {
        let core_plan = compute_media_plan_checked(facts, options, assessment)?;
        let token = new_plan_token()?;
        let summary = ContractMediaPlan {
            plan_token: token.clone(),
            target_disk_id: facts.target.disk_id.clone(),
            target_summary: format!(
                "{} (…{}): {} device — {} boot (FAT32), {} data (NTFS)",
                facts.target.model,
                facts.target.serial_suffix,
                format_bytes(facts.target.size_bytes),
                format_bytes(core_plan.layout.boot_partition_bytes),
                format_bytes(core_plan.layout.data_partition_bytes),
            ),
            // Creating media always erases the target — the warning
            // is part of every media plan, not an edge case.
            erase_warning_id: Some("media.will_erase_target".to_string()),
            boot_partition_bytes: core_plan.layout.boot_partition_bytes,
            data_partition_bytes: core_plan.layout.data_partition_bytes,
            payload_bytes: core_plan.payload_total_bytes,
            warnings: core_plan
                .warnings
                .iter()
                .map(|w| w.id().to_string())
                .chain(core_plan.safety_acknowledgments.iter().cloned())
                .chain(std::iter::once(
                    MEDIA_CREATION_UNAVAILABLE_WARNING_ID.to_string(),
                ))
                .collect(),
        };
        self.media_plans.insert(
            token,
            MediaPlanState {
                target: facts.target.clone(),
                plan: core_plan,
            },
        );
        sink(Event::MediaPlanned(summary.clone()));
        Ok(summary)
    }

    /// CreateMedia: execute the media plan bound to `plan_token`
    /// through `executor`. The token is consumed either way. Before
    /// the executor runs, all caller-supplied target facts are compared
    /// with the plan; any drift refuses with MediaPlanStale before the
    /// executor is called. Matching facts are not proof of physical
    /// identity. The built-in Windows executor independently refuses
    /// all live creation until it can bind and protect the real target.
    pub fn create_media(
        &mut self,
        plan_token: &str,
        current_target: &MediaTargetFacts,
        executor: &dyn MediaExecutor,
        sink: &mut dyn FnMut(Event),
    ) -> Result<CoreMediaPlan> {
        let state = self
            .media_plans
            .remove(plan_token)
            .ok_or(CoreError::MediaInvalidPlanToken)?;
        let planned = &state.target;
        let drift = if current_target.size_bytes != planned.size_bytes {
            Some(format!(
                "target size was {} bytes when planned, is {} bytes now",
                planned.size_bytes, current_target.size_bytes
            ))
        } else if current_target.removable != planned.removable {
            Some(format!(
                "target removable flag was {} when planned, is {} now",
                planned.removable, current_target.removable
            ))
        } else if current_target.serial_suffix != planned.serial_suffix {
            Some(format!(
                "target serial suffix was …{} when planned, is …{} now — a different device may be attached",
                planned.serial_suffix, current_target.serial_suffix
            ))
        } else if current_target.disk_id != planned.disk_id {
            Some("target disk identifier changed — a different device may be attached".to_string())
        } else if current_target.model != planned.model {
            Some("target model changed — a different device may be attached".to_string())
        } else {
            None
        };
        if let Some(detail) = drift {
            return Err(CoreError::MediaPlanStale { detail });
        }
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.building_media".to_string(),
                done,
                total,
                unit: "steps".to_string(),
            });
        };
        match executor.execute(&state.plan, &mut progress) {
            Ok(()) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Succeeded,
                    summary_id: "result.media_created".to_string(),
                });
                Ok(state.plan)
            }
            Err(e) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.media_failed".to_string(),
                });
                Err(e)
            }
        }
    }

    // -- Whole-PC (bare-metal) restore (S5) -------------------------------

    /// PlanSystemRestore: compute the bare-metal restore plan for a
    /// system set onto the target the facts describe. Erases
    /// nothing; planning refusals (not a system set, firmware
    /// problems, missing boot files, target too small) surface as
    /// their named errors. On success, emits SystemRestorePlanned
    /// with a single-use token bound to this exact plan.
    ///
    /// This entry point takes no SafeTarget context: no identity
    /// checks are performed. Shells that enumerated real disks use
    /// `plan_system_restore_guarded`.
    pub fn plan_system_restore(
        &mut self,
        backup_id: &str,
        target: &SystemRestoreTargetFacts,
        options: &SystemRestoreOptions,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractSystemRestorePlan> {
        self.plan_system_restore_inner(
            backup_id,
            target,
            options,
            &SafeTargetAssessment::no_context(),
            sink,
        )
    }

    /// PlanSystemRestore with SafeTarget enforcement (S6): the
    /// target is checked against the context's protected disks
    /// (source / backup / running media) and its own system-disk
    /// flag before planning. A refusal or an unacknowledged warning
    /// is a typed error and NO plan token is created; acknowledged
    /// warnings are recorded in the plan and its restore log. This
    /// is the entry point shells use — enforcement lives here in
    /// the engine, not in shell advice.
    pub fn plan_system_restore_guarded(
        &mut self,
        backup_id: &str,
        target: &SystemRestoreTargetFacts,
        options: &SystemRestoreOptions,
        context: &SafeTargetContext,
        target_is_system_disk: bool,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractSystemRestorePlan> {
        let assessment = assess_system_restore_target(target, target_is_system_disk, context);
        self.plan_system_restore_inner(backup_id, target, options, &assessment, sink)
    }

    fn plan_system_restore_inner(
        &mut self,
        backup_id: &str,
        target: &SystemRestoreTargetFacts,
        options: &SystemRestoreOptions,
        assessment: &SafeTargetAssessment,
        sink: &mut dyn FnMut(Event),
    ) -> Result<ContractSystemRestorePlan> {
        let manifest = read_set_manifest(&self.volume, backup_id)?;
        let core_plan =
            compute_system_restore_plan_checked(&manifest, target, options, assessment)?;
        let token = new_plan_token()?;
        let summary = ContractSystemRestorePlan {
            plan_token: token.clone(),
            backup_id: backup_id.to_string(),
            target_disk_id: target.disk_id.clone(),
            target_summary: format!(
                "{} (…{}): {} disk — {} partitions (GPT, UEFI), {} files, {} to restore",
                target.model,
                target.serial_suffix,
                format_bytes(target.size_bytes),
                core_plan.layout.len(),
                core_plan.total_file_count(),
                format_bytes(core_plan.total_apply_bytes()),
            ),
            // A system restore always erases the target disk — the
            // warning is part of every plan, not an edge case.
            erase_warning_id: Some("system_restore.will_erase_target".to_string()),
            firmware: "uefi".to_string(),
            partition_count: core_plan.layout.len() as u64,
            file_count: core_plan.total_file_count(),
            total_bytes: core_plan.total_apply_bytes(),
            warnings: core_plan
                .warnings
                .iter()
                .map(|w| w.id().to_string())
                .chain(core_plan.safety_acknowledgments.iter().cloned())
                .collect(),
        };
        self.system_restore_plans.insert(
            token,
            SystemRestorePlanState {
                target: target.clone(),
                plan: core_plan,
            },
        );
        sink(Event::SystemRestorePlanned(summary.clone()));
        Ok(summary)
    }

    /// StartSystemRestore: execute the plan bound to `plan_token`
    /// through `executor`. The token is consumed either way. Before
    /// the executor runs, the target facts are re-checked against
    /// the plan: if the disk that would be erased is not the disk
    /// the user confirmed (size, removable flag, serial suffix, or
    /// firmware mode changed), the restore refuses with
    /// SystemRestorePlanStale and the executor is never called —
    /// nothing is touched. The executor's outcome distinguishes
    /// simulated from real runs in the job summary id: a simulation
    /// never reports as a completed real restore.
    pub fn execute_system_restore(
        &mut self,
        plan_token: &str,
        current_target: &SystemRestoreTargetFacts,
        executor: &dyn SystemRestoreExecutor,
        sink: &mut dyn FnMut(Event),
    ) -> Result<SystemRestoreExecution> {
        let state = self
            .system_restore_plans
            .remove(plan_token)
            .ok_or(CoreError::SystemRestoreInvalidPlanToken)?;
        let planned = &state.target;
        let drift = if current_target.size_bytes != planned.size_bytes {
            Some(format!(
                "target size was {} bytes when planned, is {} bytes now",
                planned.size_bytes, current_target.size_bytes
            ))
        } else if current_target.removable != planned.removable {
            Some(format!(
                "target removable flag was {} when planned, is {} now",
                planned.removable, current_target.removable
            ))
        } else if current_target.serial_suffix != planned.serial_suffix {
            Some(format!(
                "target serial suffix was …{} when planned, is …{} now — a different disk may be attached",
                planned.serial_suffix, current_target.serial_suffix
            ))
        } else if current_target.firmware.value != planned.firmware.value {
            Some(
                "the target PC's firmware mode changed after planning — the plan's boot steps no longer match this machine"
                    .to_string(),
            )
        } else {
            None
        };
        if let Some(detail) = drift {
            return Err(CoreError::SystemRestorePlanStale { detail });
        }
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.restoring_system".to_string(),
                done,
                total,
                unit: "files".to_string(),
            });
        };
        match executor.execute(&self.volume, &state.plan, &mut progress) {
            Ok(execution) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Succeeded,
                    summary_id: if execution.simulated {
                        "result.system_restore_simulated".to_string()
                    } else {
                        "result.system_restore_completed".to_string()
                    },
                });
                Ok(execution)
            }
            Err(e) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.system_restore_failed".to_string(),
                });
                Err(e)
            }
        }
    }

    // -- Level-3 Boot Rehearsal (S6) --------------------------------------

    /// Plan a Boot Rehearsal: the S5 system-restore plan for the
    /// stated target, computed for a staging directory instead of a
    /// disk, plus the guided checklist for the machine-only VM
    /// steps. Erases nothing, writes nothing.
    pub fn plan_boot_rehearsal(
        &mut self,
        backup_id: &str,
        target: &SystemRestoreTargetFacts,
        options: &SystemRestoreOptions,
        staging_dir: &Path,
        vm: Option<&VmFacts>,
    ) -> Result<BootRehearsalPlan> {
        let manifest = read_set_manifest(&self.volume, backup_id)?;
        let restore_plan = compute_system_restore_plan_checked(
            &manifest,
            target,
            options,
            &SafeTargetAssessment::no_context(),
        )?;
        Ok(BootRehearsalPlan {
            checklist: vm_checklist(&restore_plan, staging_dir, vm),
            restore_plan,
            staging_dir: staging_dir.display().to_string(),
        })
    }

    /// Run a Boot Rehearsal: apply the plan to the staging
    /// directory through the S5 simulation path (the production
    /// chunk-restore code), verify the result partition by
    /// partition, write the rehearsal record, and report. A damaged
    /// set does not abort the run with a bare error: the
    /// application failure is recorded in the report and
    /// verification names the partitions that did not land. The job
    /// finishes Succeeded only when the files verify and the layout
    /// is valid; the VM boot is never claimed — see
    /// boot_rehearsal::NOT_BOOT_TESTED_LINE.
    pub fn run_boot_rehearsal(
        &mut self,
        backup_id: &str,
        target: &SystemRestoreTargetFacts,
        options: &SystemRestoreOptions,
        staging_dir: &Path,
        vm: Option<&VmFacts>,
        sink: &mut dyn FnMut(Event),
    ) -> Result<BootRehearsalReport> {
        let planned = self.plan_boot_rehearsal(backup_id, target, options, staging_dir, vm)?;
        let plan = &planned.restore_plan;
        // A new rehearsal must not replace a previous report or unrelated
        // artifacts in a user-selected directory.
        for name in [
            REHEARSAL_RECORD_FILE,
            RESTORE_LOG_FILE,
            DISKPART_SCRIPT_FILE,
        ] {
            require_absent_file(&staging_dir.join(name))?;
        }
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let executor = SimulatedDiskExecutor {
            root: staging_dir.to_path_buf(),
        };
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.boot_rehearsal".to_string(),
                done,
                total,
                unit: "files".to_string(),
            });
        };
        let application_error = match executor.execute(&self.volume, plan, &mut progress) {
            Ok(_) => None,
            Err(e) => Some(e.to_string()),
        };
        let verify = match verify_system_restore(plan, staging_dir) {
            Ok(report) => report,
            Err(error) => {
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Failed,
                    summary_id: "result.boot_rehearsal_verify_failed".to_string(),
                });
                return Err(error);
            }
        };
        let report = assemble_report(
            plan,
            staging_dir,
            &verify,
            application_error,
            vm,
            now_unix(),
        );
        if let Err(error) = write_new_rehearsal_record(staging_dir, &report) {
            sink(Event::JobFinished {
                job_id,
                outcome: JobOutcome::Failed,
                summary_id: "result.boot_rehearsal_verify_failed".to_string(),
            });
            return Err(error);
        }
        sink(Event::JobFinished {
            job_id,
            outcome: if report.passed() {
                JobOutcome::Succeeded
            } else {
                JobOutcome::Failed
            },
            summary_id: if report.files_verified {
                "result.boot_rehearsal_files_verified".to_string()
            } else {
                "result.boot_rehearsal_verify_failed".to_string()
            },
        });
        Ok(report)
    }

    // -- Level-2 File Rehearsal ------------------------------------------

    /// StartFileRehearsal job: restore `chosen` files (set paths) plus a
    /// deterministic pseudo-random sample of `sample_count` other files
    /// into a fresh sandbox directory, and byte-compare every restored
    /// file against its manifest hash. The sandbox is removed afterwards
    /// unless `keep_sandbox` is set.
    pub fn start_file_rehearsal(
        &mut self,
        set_id: &str,
        chosen: &[String],
        sample_count: usize,
        keep_sandbox: bool,
        sink: &mut dyn FnMut(Event),
    ) -> Result<FileRehearsalReport> {
        let manifest = read_set_manifest(&self.volume, set_id)?;
        validate_restore_manifest(&manifest)?;
        let selected = select_rehearsal_files(&manifest, chosen, sample_count)?;
        let temp_root = std::env::temp_dir();
        inspect_directory(&temp_root)?;
        let sandbox = temp_root.join(format!(
            "safereturn-rehearsal-{}-{}",
            std::process::id(),
            crate::hex::encode(&crate::crypto::random_array::<16>()?)
        ));
        // An existing directory or link is never adopted as our sandbox.
        std::fs::create_dir(&sandbox).map_err(|e| crate::error::io_at(&sandbox, e))?;
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let total = selected.len() as u64;
        let mut entries = Vec::with_capacity(selected.len());
        for (i, entry) in selected.iter().enumerate() {
            entries.push(rehearse_one(&self.volume, entry, &sandbox));
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.file_rehearsal".to_string(),
                done: i as u64 + 1,
                total,
                unit: "files".to_string(),
            });
        }
        let passed = entries.iter().all(|e| e.passed);
        if !keep_sandbox {
            let _ = std::fs::remove_dir_all(&sandbox);
        }
        sink(Event::JobFinished {
            job_id,
            outcome: if passed {
                JobOutcome::Succeeded
            } else {
                JobOutcome::Failed
            },
            summary_id: if passed {
                "result.file_rehearsal_passed".to_string()
            } else {
                "result.file_rehearsal_failed".to_string()
            },
        });
        Ok(FileRehearsalReport {
            set_id: set_id.to_string(),
            sandbox,
            kept_sandbox: keep_sandbox,
            entries,
        })
    }
}

fn plan_entries(
    manifest: &SetManifest,
    target_dir: &std::path::Path,
    only_path: Option<&str>,
    backup_id: &str,
) -> Result<Vec<(SetFileEntry, PathBuf)>> {
    match only_path {
        None => manifest
            .files
            .iter()
            .map(|f| Ok((f.clone(), join_relative(target_dir, &f.path)?)))
            .collect(),
        Some(p) => {
            let entry = manifest.file(p).ok_or_else(|| CoreError::FileNotInSet {
                set_id: backup_id.to_string(),
                path: p.to_string(),
            })?;
            let file_name = p.rsplit('/').next().unwrap_or(p);
            Ok(vec![(entry.clone(), join_relative(target_dir, file_name)?)])
        }
    }
}

fn states_for_entries(
    entries: &[(SetFileEntry, PathBuf)],
) -> Result<BTreeMap<String, Option<String>>> {
    let mut map = BTreeMap::new();
    for (entry, dest) in entries {
        map.insert(entry.path.clone(), hash_existing_file(dest)?);
    }
    Ok(map)
}

fn new_plan_token() -> Result<String> {
    Ok(crate::hex::encode(&crate::crypto::random_array::<32>()?))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRehearsalEntry {
    pub path: String,
    pub passed: bool,
    /// Plain-language detail: "restored and matched byte-for-byte" or the
    /// named failure (damaged chunk id, hash mismatch, …).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRehearsalReport {
    pub set_id: String,
    /// Sandbox the sample was restored into (removed unless kept).
    pub sandbox: PathBuf,
    pub kept_sandbox: bool,
    pub entries: Vec<FileRehearsalEntry>,
}

impl FileRehearsalReport {
    pub fn passed(&self) -> bool {
        self.entries.iter().all(|e| e.passed)
    }

    pub fn passed_count(&self) -> usize {
        self.entries.iter().filter(|e| e.passed).count()
    }
}

fn rehearse_one(
    volume: &UnlockedVolume,
    entry: &SetFileEntry,
    sandbox: &std::path::Path,
) -> FileRehearsalEntry {
    let fail = |detail: String| FileRehearsalEntry {
        path: entry.path.clone(),
        passed: false,
        detail,
    };
    let dest = match join_relative(sandbox, &entry.path) {
        Ok(dest) => dest,
        Err(e) => return fail(format!("could not be restored: {e}")),
    };
    // Exercise the same streaming, verified publication path as file restore.
    if let Err(e) = restore_entries(
        volume,
        &[(entry.clone(), dest.clone())],
        &HashSet::new(),
        &mut |_, _| {},
    ) {
        return fail(format!("could not be restored: {e}"));
    }
    match hash_existing_file(&dest) {
        Ok(Some(h)) if h == entry.sha256 => FileRehearsalEntry {
            path: entry.path.clone(),
            passed: true,
            detail: "restored and matched byte-for-byte".to_string(),
        },
        Ok(_) => fail("restored file's hash does not match the backup record".to_string()),
        Err(e) => fail(format!("could not re-read the restored file: {e}")),
    }
}

/// Chosen files first (in the order given), then the deterministic
/// sample. Sampling: partial Fisher–Yates driven by a xorshift64* PRNG
/// seeded from the set id — same set + same counts ⇒ same sample, on
/// every machine, so rehearsal results are reproducible and comparable.
pub fn select_rehearsal_files(
    manifest: &SetManifest,
    chosen: &[String],
    sample_count: usize,
) -> Result<Vec<SetFileEntry>> {
    let mut selected: Vec<SetFileEntry> = Vec::new();
    let mut taken: HashSet<&str> = HashSet::new();
    for path in chosen {
        let entry = manifest.file(path).ok_or_else(|| CoreError::FileNotInSet {
            set_id: manifest.set_id.clone(),
            path: path.clone(),
        })?;
        if taken.insert(entry.path.as_str()) {
            selected.push(entry.clone());
        }
    }
    let mut pool: Vec<&SetFileEntry> = manifest
        .files
        .iter()
        .filter(|f| !taken.contains(f.path.as_str()))
        .collect();
    let want = sample_count.min(pool.len());
    let mut rng = XorShift64(seed_from_set_id(&manifest.set_id));
    for i in 0..want {
        let j = i + (rng.next() % (pool.len() - i) as u64) as usize;
        pool.swap(i, j);
        selected.push(pool[i].clone());
    }
    Ok(selected)
}

fn seed_from_set_id(set_id: &str) -> u64 {
    // FNV-1a over the set id — a stable, documented seed (not crypto;
    // it only picks which files get sampled).
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in set_id.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 {
        0x9e3779b97f4a7c15
    } else {
        hash
    }
}

struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}
