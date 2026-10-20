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
//!   that exact token, consumes it, and — before writing anything —
//!   re-checks that every target file is still in the state the plan
//!   described. A changed target makes the plan stale and the restore
//!   refuses with nothing written. There is no other restore entry point
//!   in this API, so "execute without a token" is an unknown-token error.
//! - Level-2 File Rehearsal restores chosen files plus a deterministic
//!   pseudo-random sample into a temporary sandbox and compares hashes;
//!   the sample is reproducible (seeded from the set id), so a rehearsal
//!   result can be re-run and compared.

use crate::capture::{CaptureSource, LiveSource};
use crate::error::{CoreError, Result};
use crate::sets::{
    backup_tree_with_source, hash_existing_file, list_sets, read_set_manifest, restore_entries,
    verify_set, BackupOutcome, RestoreOutcome, SetFileEntry, SetManifest, SetVerifyReport,
    TargetState,
};
use crate::volume::UnlockedVolume;
use safereturn_contract::{BackupSummary, Event, JobOutcome, RestorePlan};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

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
    /// Target state per set path at plan time — staleness reference.
    states: BTreeMap<String, TargetState>,
    /// Set paths whose plan-time state was Differs (approved overwrites).
    overwrites: HashSet<String>,
}

pub struct Engine {
    volume: UnlockedVolume,
    job_counter: u64,
    plans: HashMap<String, PlanState>,
}

impl Engine {
    pub fn new(volume: UnlockedVolume) -> Self {
        Self {
            volume,
            job_counter: 0,
            plans: HashMap::new(),
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
    /// only reads while the caller's session is alive.
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
        let mut progress = |done: u64, total: u64| {
            sink(Event::JobProgress {
                job_id: job_id.clone(),
                phase_id: "phase.copying_files".to_string(),
                done,
                total,
                unit: "files".to_string(),
            });
        };
        match backup_tree_with_source(volume, source, label, roots, now_unix(), &mut progress) {
            Ok(outcome) => {
                // The catalog is a rebuildable cache over the manifests;
                // refresh it, but its failure must not misreport a backup
                // that did succeed — manifests remain the source of truth.
                let _ = crate::sets::rebuild_catalog(volume);
                sink(Event::JobFinished {
                    job_id,
                    outcome: JobOutcome::Succeeded,
                    summary_id: "result.backup_succeeded".to_string(),
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
                unit: "chunks".to_string(),
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
        let entries = plan_entries(&manifest, target_dir, only_path, backup_id)?;
        let states = states_for_entries(&entries)?;
        let overwrite_count = states
            .values()
            .filter(|s| **s == TargetState::Differs)
            .count() as u64;
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
        let overwrites: HashSet<String> = states
            .iter()
            .filter(|(_, s)| **s == TargetState::Differs)
            .map(|(p, _)| p.clone())
            .collect();
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
                Some(now) => {
                    return Err(CoreError::PlanStale {
                        detail: format!("{path} was {planned:?} when planned, is {now:?} now"),
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
        match restore_entries(volume, &plan.entries, &plan.overwrites, &mut progress) {
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
        let selected = select_rehearsal_files(&manifest, chosen, sample_count)?;
        let job_id = self.next_job_id();
        sink(Event::JobStarted {
            job_id: job_id.clone(),
        });
        let sandbox = std::env::temp_dir().join(format!(
            "safereturn-rehearsal-{}-{}",
            std::process::id(),
            crate::hex::encode(&crate::crypto::random_array::<4>()?)
        ));
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
        None => Ok(manifest
            .files
            .iter()
            .map(|f| (f.clone(), target_dir.join(&f.path)))
            .collect()),
        Some(p) => {
            let entry = manifest.file(p).ok_or_else(|| CoreError::FileNotInSet {
                set_id: backup_id.to_string(),
                path: p.to_string(),
            })?;
            let file_name = p.rsplit('/').next().unwrap_or(p);
            Ok(vec![(entry.clone(), target_dir.join(file_name))])
        }
    }
}

fn states_for_entries(
    entries: &[(SetFileEntry, PathBuf)],
) -> Result<BTreeMap<String, TargetState>> {
    let mut map = BTreeMap::new();
    for (entry, dest) in entries {
        let state = match hash_existing_file(dest)? {
            None => TargetState::Absent,
            Some(h) if h == entry.sha256 => TargetState::Identical,
            Some(_) => TargetState::Differs,
        };
        map.insert(entry.path.clone(), state);
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
    let dest = sandbox.join(&entry.path);
    let fail = |detail: String| FileRehearsalEntry {
        path: entry.path.clone(),
        passed: false,
        detail,
    };
    // Rebuild the file from its chunks exactly as a restore would.
    let mut content = Vec::with_capacity(entry.size as usize);
    for chunk_id in &entry.chunks {
        match volume.get_chunk(chunk_id) {
            Ok(bytes) => content.extend_from_slice(&bytes),
            Err(e) => return fail(format!("could not be restored: {e}")),
        }
    }
    if content.len() as u64 != entry.size {
        return fail("restored size does not match the backup record".to_string());
    }
    if let Some(parent) = dest.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            return fail(format!("sandbox write failed: {e}"));
        }
    }
    if let Err(e) = std::fs::write(&dest, &content) {
        return fail(format!("sandbox write failed: {e}"));
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
