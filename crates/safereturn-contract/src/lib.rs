//! SafeReturn shell contract — the single source of truth for messages
//! between shells (WinUI 3 desktop, Win32 WinPE, CLI) and the Rust engine.
//! See files/SHELL_CONTRACT.md. Golden JSON fixtures in ../golden are
//! generated from these types; the C# shell's tests deserialize them all,
//! so a shape change fails a test on one side before it reaches a user.

use serde::{Deserialize, Serialize};

pub const CONTRACT_VERSION: u32 = 1;

/// Which shell is talking. Presentation differs; behavior must not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellKind {
    WinUiDesktop,
    Win32Recovery,
    Cli,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Hello {
        contract_version: u32,
        shell: ShellKind,
        shell_version: String,
    },
    ListDisks,
    PlanBackup {
        destination_disk_id: String,
    },
    StartBackup {
        destination_disk_id: String,
        /// Passed once, held by the engine in protected memory for the job
        /// only, never logged, never echoed. (Transport security: SHELL_CONTRACT §3.)
        password: String,
    },
    StartVerify {
        backup_id: String,
    },
    CancelJob {
        job_id: String,
    },
    /// List the backup sets on the opened volume (S2).
    ListBackups,
    /// Ask the engine to plan a file restore (S2). With `path: None` the
    /// plan covers the whole set into `target_dir`; with `path: Some(p)`
    /// it covers the single file `p`, restored into `target_dir` under
    /// its file name. The engine answers RestorePlanned with a plan
    /// token; nothing is written by planning.
    PlanRestore {
        backup_id: String,
        target_dir: String,
        path: Option<String>,
    },
    /// Execute the restore plan identified by `plan_token` — the exact
    /// token from the RestorePlanned event the user confirmed. Tokens
    /// are single-use and go stale if the target changes (S2).
    StartRestore {
        plan_token: String,
    },
    /// Level-2 File Rehearsal (S2): restore the chosen files (plus an
    /// engine-picked deterministic sample) into a sandbox and compare
    /// them byte-for-byte against the set manifest.
    StartFileRehearsal {
        backup_id: String,
        paths: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiskInfo {
    pub disk_id: String,
    pub model: String,
    /// Last 4 of serial — enough for a human to identify a drive, not the whole serial.
    pub serial_suffix: String,
    pub size_bytes: u64,
    pub free_bytes: u64,
    pub is_system_disk: bool,
    pub is_removable: bool,
    /// Strings-table ids, rendered by the shell — never raw text from the engine
    /// for anything user-visible in a flow (diagnostics excepted).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceVerdict {
    Fits,
    Tight,
    TooSmall,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupPlan {
    pub destination_disk_id: String,
    pub estimated_backup_bytes: u64,
    pub destination_free_bytes: u64,
    pub verdict: SpaceVerdict,
    /// Strings-table ids + args, in display order — the "what will happen" summary.
    pub summary_line_ids: Vec<String>,
}

/// One backup set as listed for the user (S2). Facts only — counts and
/// sizes from the set manifest, never a derived "health" figure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackupSummary {
    pub backup_id: String,
    pub label: String,
    pub created_unix: u64,
    pub file_count: u64,
    pub total_bytes: u64,
}

/// The engine's answer to PlanRestore (S2): everything the user is being
/// asked to confirm, plus the token that binds StartRestore to *this*
/// preview. `target_summary` is data (paths and counts), like
/// DiskInfo.model — the flow wording around it is strings-table copy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestorePlan {
    pub plan_token: String,
    pub backup_id: String,
    pub target_summary: String,
    /// Strings-table id of the overwrite warning, present only when
    /// existing files would be replaced.
    pub erase_warning_id: Option<String>,
    pub file_count: u64,
    pub total_bytes: u64,
    pub overwrite_count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Welcome {
        contract_version: u32,
        engine_version: String,
    },
    Incompatible {
        minimum_contract_version: u32,
    },
    DiskList {
        disks: Vec<DiskInfo>,
    },
    BackupPlanned(BackupPlan),
    BackupList {
        backups: Vec<BackupSummary>,
    },
    RestorePlanned(RestorePlan),
    JobStarted {
        job_id: String,
    },
    JobProgress {
        job_id: String,
        /// Strings-table id for the phase label (e.g. "phase.taking_snapshot").
        phase_id: String,
        done: u64,
        total: u64,
        /// "bytes", "files", "chunks" — the shell formats numbers, the engine owns units.
        unit: String,
    },
    JobFinished {
        job_id: String,
        outcome: JobOutcome,
        /// Strings-table id of the outcome summary (facts, never a health score).
        summary_id: String,
    },
    Error {
        /// Stable machine code, e.g. "vss.writer_failed".
        code: String,
        /// Strings-table id for the user-facing message.
        message_id: String,
        /// What was NOT changed — a required honesty field, may be a strings id.
        what_was_not_changed_id: String,
    },
}

/// Every message on the wire is one JSON object per line, wrapped so the
/// first field a reader sees says which direction and kind it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WireMessage {
    Request { id: u64, body: Request },
    Event(Event),
}
