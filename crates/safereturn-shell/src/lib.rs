//! The WinPE recovery shell's view-model (S6, slice 2): the pure
//! screen state machine of the recovery flow.
//!
//! ## Why this crate exists (and why it is not in core or the shell binary)
//!
//! SHELL_CONTRACT §2.1: shells render; the engine decides. But a
//! renderer still needs *some* logic — which screen follows which,
//! which control a picker row enables, what a destructive confirm
//! defaults to. That logic is presentation logic, and it belongs to
//! the shell side; what it must never contain is backup/restore/
//! safety *decisions* (those are the engine's, enforced again
//! engine-side by the plan-token and SafeTarget machinery).
//!
//! Putting the state machine in its own crate — not in
//! `safereturn-core` (the engine library; shells must not grow
//! inside it) and not in the Win32 binary (untestable there: Win32
//! code only compiles for Windows, and this machine-checkable flow
//! logic must run in the full local gate on every OS) — keeps the
//! front-end a thin renderer and the flow fully testable with
//! scripted engine events.
//!
//! ## The boundary
//!
//! The view-model consumes contract `Event`s and produces contract
//! `Request`s — the same wire messages the desktop shell exchanges
//! over its pipe (SHELL_CONTRACT §3: in PE the transport is
//! in-process, the message types are the boundary). Host-only work
//! (writing the S4 boot-test marker, exiting) is expressed as
//! `ShellEffect`s the front-end performs. All user-visible wording
//! is strings-table ids from `strings` (shell copy) or from the
//! contract/core (plan warnings, phase ids, summary ids, SafeTarget
//! ids) — the view-model invents no text.
//!
//! ## Flow
//!
//! Boot → Welcome (media check + boot-test marker) → Choose backup →
//! Choose kind (files / whole PC / rehearse) → Choose target
//! (SafeTarget verdicts rendered; engine re-checks at plan time) →
//! [Override confirm when the engine demands one] → Plan confirm
//! (engine summary + erase warning; Cancel is the default) →
//! Progress → Result. Plan-stale and engine errors land on their
//! own screens with a way back — never a dead end, never a silent
//! failure.

pub mod strings;
pub mod view;

use safereturn_contract::{
    BackupSummary, DiskInfo, Event, JobOutcome, Request, ShellKind, CONTRACT_VERSION,
};
use safereturn_core::{
    check_target, BootTestStatus, MediaVerifyReport, SafeTargetContext, TargetDiskFacts,
};
use serde::{Deserialize, Serialize};
use strings::*;
use view::*;

/// The host's media check, distilled from the S4 `verify_media`
/// report into the facts the Welcome screen renders. The boot-test
/// status is kept separate from "media intact" exactly as the S4
/// report keeps them: two facts, never conflated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaCheckFacts {
    pub plan_id: String,
    /// Payload hashes + boot files all present and matching.
    pub intact: bool,
    /// The named problem when not intact (first failing component).
    pub problem: Option<String>,
    pub boot_test: BootTestFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootTestFact {
    NotTested,
    Tested,
    Partial,
    Invalid,
}

impl MediaCheckFacts {
    pub fn from_report(report: &MediaVerifyReport) -> Self {
        let problem = if report.passed() {
            None
        } else if let Some(p) = report.payload.iter().find(|p| !p.ok) {
            Some(format!("{}: {}", p.dest_rel, p.detail))
        } else if let Some(b) = report.boot_files.iter().find(|b| !b.present) {
            Some(format!("boot file {} is missing", b.path))
        } else {
            Some("media check failed".to_string())
        };
        Self {
            plan_id: report.manifest.plan_id.clone(),
            intact: report.passed(),
            problem,
            boot_test: match &report.boot_test {
                BootTestStatus::NotTested => BootTestFact::NotTested,
                BootTestStatus::Tested { .. } => BootTestFact::Tested,
                BootTestStatus::BootStartedShellNotReached { .. } => BootTestFact::Partial,
                BootTestStatus::Invalid { .. } => BootTestFact::Invalid,
            },
        }
    }
}

/// Everything the host hands the view-model at start. All of it is
/// *facts the host measured* (media verification, disk identities
/// for SafeTarget, where files may be restored) — decisions remain
/// the engine's.
#[derive(Debug, Clone, Default)]
pub struct ShellConfig {
    pub shell_version: String,
    /// The host's verify_media result for the media this shell
    /// booted from; None when the host could not check (the Welcome
    /// screen says so — it does not guess).
    pub media: Option<MediaCheckFacts>,
    /// Protected-disk identities for SafeTarget rendering. The
    /// engine adapter holds its own copy for enforcement; the
    /// view-model's verdicts are the same computation, rendered.
    pub safe_target: SafeTargetContext,
    /// Disks the running media booted from is identified by this
    /// disk_id (also present in the SafeTarget context as
    /// media_disk when the host could identify it).
    pub media_disk_id: Option<String>,
    /// Per-disk folder a file restore may write into, as the host
    /// resolved it in WinPE (disk_id → target dir). A disk with no
    /// entry cannot be a file-restore target.
    pub file_restore_dirs: Vec<(String, String)>,
}

/// Which restore the user picked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreKind {
    Files,
    WholePc,
    Rehearse,
}

#[derive(Debug, Clone, PartialEq)]
enum Stage {
    Boot,
    Welcome,
    ChooseBackup,
    ChooseKind,
    ChooseTarget,
    OverrideConfirm {
        warning_id: String,
        disk_id: String,
    },
    PlanConfirm,
    Running,
    Result {
        outcome: JobOutcome,
        summary_id: String,
    },
    PlanStale,
    Error {
        code: String,
        message_id: String,
        what_was_not_changed_id: String,
    },
    Exited,
}

/// The recovery shell's view-model. Drive it with `start()`,
/// `on_event()` (engine events) and `on_action()` (control
/// presses); render `screen()` after each call.
pub struct PeShellViewModel {
    config: ShellConfig,
    stage: Stage,
    backups: Option<Vec<BackupSummary>>,
    disks: Option<Vec<DiskInfo>>,
    backup_id: Option<String>,
    kind: Option<RestoreKind>,
    disk_id: Option<String>,
    awaiting_plan: bool,
    plan_token: Option<String>,
    plan_target_summary: Option<String>,
    plan_erase_warning_id: Option<String>,
    plan_warnings: Vec<String>,
    plan_file_count: u64,
    plan_total_bytes: u64,
    job_id: Option<String>,
    progress: Option<ProgressView>,
    boot_marker: Option<bool>,
    effects: Vec<ShellEffect>,
}

impl PeShellViewModel {
    pub fn new(config: ShellConfig) -> Self {
        Self {
            config,
            stage: Stage::Boot,
            backups: None,
            disks: None,
            backup_id: None,
            kind: None,
            disk_id: None,
            awaiting_plan: false,
            plan_token: None,
            plan_target_summary: None,
            plan_erase_warning_id: None,
            plan_warnings: Vec::new(),
            plan_file_count: 0,
            plan_total_bytes: 0,
            job_id: None,
            progress: None,
            boot_marker: None,
            effects: Vec::new(),
        }
    }

    /// Shell start: say Hello, and — when the host checked the
    /// media — ask the front-end to record this boot on it (the S4
    /// boot-test marker protocol: a boot that reaches the shell is
    /// what makes media "boot-tested").
    pub fn start(&mut self) -> Vec<Request> {
        if let Some(media) = &self.config.media {
            self.effects.push(ShellEffect::RecordBootTest {
                media_plan_id: media.plan_id.clone(),
            });
        }
        vec![Request::Hello {
            contract_version: CONTRACT_VERSION,
            shell: ShellKind::Win32Recovery,
            shell_version: if self.config.shell_version.is_empty() {
                env!("CARGO_PKG_VERSION").to_string()
            } else {
                self.config.shell_version.clone()
            },
        }]
    }

    /// Drain the effects the front-end must perform.
    pub fn take_effects(&mut self) -> Vec<ShellEffect> {
        std::mem::take(&mut self.effects)
    }

    // -- engine events -------------------------------------------------------

    pub fn on_event(&mut self, event: Event) -> Vec<Request> {
        match event {
            Event::Welcome { .. } => {
                if self.stage == Stage::Boot {
                    self.stage = Stage::Welcome;
                    // Prefetch both lists so the picker screens are
                    // populated when reached; late answers simply
                    // refresh the screen that shows them.
                    return vec![Request::ListBackups, Request::ListDisks];
                }
                Vec::new()
            }
            Event::Incompatible { .. } => {
                self.stage = Stage::Error {
                    code: "shell.incompatible".to_string(),
                    message_id: BODY_INCOMPATIBLE.to_string(),
                    what_was_not_changed_id: "shell.error.nothing_changed".to_string(),
                };
                Vec::new()
            }
            Event::BackupList { backups } => {
                self.backups = Some(backups);
                Vec::new()
            }
            Event::DiskList { disks } => {
                self.disks = Some(disks);
                Vec::new()
            }
            Event::RestorePlanned(plan) => {
                if self.stage == Stage::ChooseTarget && self.kind == Some(RestoreKind::Files) {
                    self.awaiting_plan = false;
                    self.plan_token = Some(plan.plan_token);
                    self.plan_target_summary = Some(plan.target_summary);
                    self.plan_erase_warning_id = plan.erase_warning_id;
                    self.plan_warnings = Vec::new();
                    self.plan_file_count = plan.file_count;
                    self.plan_total_bytes = plan.total_bytes;
                    self.stage = Stage::PlanConfirm;
                }
                Vec::new()
            }
            Event::SystemRestorePlanned(plan) => {
                if self.stage == Stage::ChooseTarget && self.kind == Some(RestoreKind::WholePc) {
                    self.awaiting_plan = false;
                    self.plan_token = Some(plan.plan_token);
                    self.plan_target_summary = Some(plan.target_summary);
                    self.plan_erase_warning_id = plan.erase_warning_id;
                    self.plan_warnings = plan.warnings;
                    self.plan_file_count = plan.file_count;
                    self.plan_total_bytes = plan.total_bytes;
                    self.stage = Stage::PlanConfirm;
                }
                Vec::new()
            }
            Event::JobStarted { job_id } => {
                if self.stage == Stage::Running {
                    self.job_id = Some(job_id);
                }
                Vec::new()
            }
            Event::JobProgress {
                phase_id,
                done,
                total,
                unit,
                ..
            } => {
                if self.stage == Stage::Running {
                    self.progress = Some(ProgressView {
                        phase_id,
                        done,
                        total,
                        unit,
                    });
                }
                Vec::new()
            }
            Event::JobFinished {
                outcome,
                summary_id,
                ..
            } => {
                if self.stage == Stage::Running {
                    self.stage = Stage::Result {
                        outcome,
                        summary_id,
                    };
                }
                Vec::new()
            }
            Event::Error {
                code,
                message_id,
                what_was_not_changed_id,
            } => {
                self.on_error(code, message_id, what_was_not_changed_id);
                Vec::new()
            }
            // Backup/media planning belong to the desktop flow; the
            // PE subset never requests them.
            Event::BackupPlanned(_) | Event::MediaPlanned(_) => Vec::new(),
        }
    }

    fn on_error(&mut self, code: String, message_id: String, what_was_not_changed_id: String) {
        // A plan the engine refused for staleness, discovered when
        // the job was started: its own screen, with a re-plan path.
        if (code == "system_restore.plan_stale" || code == "restore.plan_stale")
            && self.stage == Stage::Running
        {
            self.stage = Stage::PlanStale;
            return;
        }
        // The engine demands an explicit SafeTarget override before
        // it will plan this target: ask for it on its own screen
        // (default = go back), then retry the plan.
        if code == "target.override_required" && self.stage == Stage::ChooseTarget {
            self.awaiting_plan = false;
            if let Some(disk_id) = self.disk_id.clone() {
                self.stage = Stage::OverrideConfirm {
                    warning_id: message_id,
                    disk_id,
                };
                return;
            }
        }
        // An error after the result is already shown changes
        // nothing on screen (engine flows can emit JobFinished and
        // then surface the error that caused it).
        if matches!(self.stage, Stage::Result { .. }) {
            return;
        }
        self.awaiting_plan = false;
        self.stage = Stage::Error {
            code,
            message_id,
            what_was_not_changed_id,
        };
    }

    // -- user actions ----------------------------------------------------------

    pub fn on_action(&mut self, action: ShellAction) -> Vec<Request> {
        match action {
            ShellAction::BootMarkerWritten { ok } => {
                self.boot_marker = Some(ok);
                Vec::new()
            }
            ShellAction::Exit => {
                self.stage = Stage::Exited;
                self.effects.push(ShellEffect::ExitShell);
                Vec::new()
            }
            ShellAction::Restart => {
                // Restarting is the host's business (in WinPE, the
                // user restarts from the Exit screen's guidance);
                // the view-model only leaves the shell.
                self.stage = Stage::Exited;
                self.effects.push(ShellEffect::ExitShell);
                Vec::new()
            }
            ShellAction::Continue => {
                if self.stage == Stage::Welcome {
                    self.stage = Stage::ChooseBackup;
                }
                Vec::new()
            }
            ShellAction::Back => {
                self.back();
                Vec::new()
            }
            ShellAction::SelectBackup { backup_id } => {
                if self.stage == Stage::ChooseBackup
                    && self
                        .backups
                        .as_ref()
                        .is_some_and(|b| b.iter().any(|s| s.backup_id == backup_id))
                {
                    self.backup_id = Some(backup_id);
                    self.stage = Stage::ChooseKind;
                }
                Vec::new()
            }
            ShellAction::ChooseFiles => self.choose_kind(RestoreKind::Files),
            ShellAction::ChooseWholePc => self.choose_kind(RestoreKind::WholePc),
            ShellAction::ChooseRehearse => {
                if self.stage == Stage::ChooseKind {
                    if let Some(backup_id) = self.backup_id.clone() {
                        self.kind = Some(RestoreKind::Rehearse);
                        self.stage = Stage::Running;
                        self.job_id = None;
                        self.progress = None;
                        return vec![Request::StartFileRehearsal {
                            backup_id,
                            paths: Vec::new(),
                        }];
                    }
                }
                Vec::new()
            }
            ShellAction::SelectTarget { disk_id } => self.select_target(disk_id),
            ShellAction::ConfirmOverride => {
                if let Stage::OverrideConfirm {
                    warning_id,
                    disk_id,
                } = self.stage.clone()
                {
                    self.effects.push(ShellEffect::AcknowledgeWarning {
                        warning_id: warning_id.clone(),
                    });
                    self.stage = Stage::ChooseTarget;
                    // Re-issue the same plan request; the adapter
                    // now holds the acknowledgment, so the engine
                    // plans with the override recorded.
                    return self.plan_request_for(&disk_id);
                }
                Vec::new()
            }
            ShellAction::ConfirmPlan => {
                if self.stage == Stage::PlanConfirm {
                    if let Some(token) = self.plan_token.take() {
                        self.stage = Stage::Running;
                        self.job_id = None;
                        self.progress = None;
                        return vec![match self.kind {
                            Some(RestoreKind::WholePc) => {
                                Request::StartSystemRestore { plan_token: token }
                            }
                            _ => Request::StartRestore { plan_token: token },
                        }];
                    }
                }
                Vec::new()
            }
            ShellAction::CancelJob => {
                if self.stage == Stage::Running {
                    if let Some(job_id) = self.job_id.clone() {
                        return vec![Request::CancelJob { job_id }];
                    }
                }
                Vec::new()
            }
        }
    }

    fn choose_kind(&mut self, kind: RestoreKind) -> Vec<Request> {
        if self.stage == Stage::ChooseKind {
            self.kind = Some(kind);
            self.stage = Stage::ChooseTarget;
        }
        Vec::new()
    }

    fn back(&mut self) {
        self.stage = match &self.stage {
            Stage::ChooseBackup => Stage::Welcome,
            Stage::ChooseKind => Stage::ChooseBackup,
            Stage::ChooseTarget => Stage::ChooseKind,
            Stage::OverrideConfirm { .. } => Stage::ChooseTarget,
            Stage::PlanConfirm => Stage::ChooseTarget,
            Stage::PlanStale => Stage::ChooseTarget,
            Stage::Result { .. } => Stage::Welcome,
            Stage::Error { .. } => {
                // Errors during planning return to the target pick;
                // anything else returns to the start.
                if self.backup_id.is_some() && self.kind.is_some() {
                    Stage::ChooseTarget
                } else {
                    Stage::Welcome
                }
            }
            other => other.clone(),
        };
        self.awaiting_plan = false;
    }

    fn select_target(&mut self, disk_id: String) -> Vec<Request> {
        if self.stage != Stage::ChooseTarget || self.awaiting_plan {
            return Vec::new();
        }
        if self.kind.is_none() {
            return Vec::new();
        }
        // A row the screen marked unselectable stays unselectable
        // even if a front-end bug (or a scripted caller) emits the
        // action anyway — the view-model re-derives the verdict
        // rather than trusting the render.
        let rows = self.target_rows();
        match rows.iter().find(|r| r.id == disk_id) {
            Some(row) if row.selectable => {}
            _ => return Vec::new(),
        }
        self.disk_id = Some(disk_id.clone());
        self.plan_request_for(&disk_id)
    }

    fn plan_request_for(&mut self, disk_id: &str) -> Vec<Request> {
        let Some(backup_id) = self.backup_id.clone() else {
            return Vec::new();
        };
        match self.kind {
            Some(RestoreKind::WholePc) => {
                self.awaiting_plan = true;
                vec![Request::PlanSystemRestore {
                    backup_id,
                    target_disk_id: disk_id.to_string(),
                }]
            }
            Some(RestoreKind::Files) => {
                self.awaiting_plan = true;
                let target_dir = self
                    .config
                    .file_restore_dirs
                    .iter()
                    .find(|(id, _)| id == disk_id)
                    .map(|(_, dir)| dir.clone())
                    .unwrap_or_default();
                vec![Request::PlanRestore {
                    backup_id,
                    target_dir,
                    path: None,
                }]
            }
            _ => Vec::new(),
        }
    }

    // -- SafeTarget rendering ------------------------------------------------

    /// The verdict for one disk in the current flow, as data:
    /// (selectable, note id, note is refusal).
    fn disk_verdict(&self, disk: &DiskInfo) -> (bool, Option<String>, bool) {
        let candidate = TargetDiskFacts::from(disk);
        let assessment = check_target(&candidate, &self.config.safe_target);
        let refusal = assessment.first_refusal().map(|(id, _)| id.to_string());
        let first_warning = assessment.warnings().first().map(|(id, _)| id.to_string());
        match self.kind {
            Some(RestoreKind::WholePc) => {
                // Destructive flow: SafeTarget verdicts bind.
                if let Some(id) = refusal {
                    (false, Some(id), true)
                } else if let Some(id) = first_warning {
                    (true, Some(id), false)
                } else {
                    (true, None, false)
                }
            }
            Some(RestoreKind::Files) => {
                // File restore erases nothing on the target disk,
                // so identity verdicts are shown as notes — except
                // the running media's own disk (in WinPE a RAM disk:
                // restored files there vanish at reboot and can
                // exhaust memory) and disks the host gave no
                // restore folder for.
                if self.config.media_disk_id.as_deref() == Some(disk.disk_id.as_str()) {
                    (
                        false,
                        Some(safereturn_core::REASON_IS_MEDIA_DISK.to_string()),
                        true,
                    )
                } else if !self
                    .config
                    .file_restore_dirs
                    .iter()
                    .any(|(id, _)| id == &disk.disk_id)
                {
                    (false, Some(BODY_TARGET_NO_PATH.to_string()), true)
                } else if let Some(id) = first_warning.or(refusal) {
                    (true, Some(id), false)
                } else {
                    (true, None, false)
                }
            }
            _ => (true, None, false),
        }
    }

    fn target_rows(&self) -> Vec<ListRow> {
        let Some(disks) = &self.disks else {
            return Vec::new();
        };
        disks
            .iter()
            .map(|d| {
                let (selectable, note_id, note_is_refusal) = self.disk_verdict(d);
                ListRow {
                    id: d.disk_id.clone(),
                    text_id: BODY_TARGET_ROW.to_string(),
                    args: vec![
                        d.model.clone(),
                        d.serial_suffix.clone(),
                        safereturn_core::format_bytes(d.size_bytes),
                    ],
                    selectable,
                    note_id,
                    note_is_refusal,
                }
            })
            .collect()
    }

    /// The engine error code of the current Error screen, for
    /// host diagnostics (the user sees the message id's text, never
    /// the raw code).
    pub fn current_error_code(&self) -> Option<&str> {
        match &self.stage {
            Stage::Error { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }

    // -- screens ---------------------------------------------------------------

    pub fn screen(&self) -> ScreenView {
        match &self.stage {
            Stage::Boot => ScreenView {
                screen: ScreenId::Boot,
                title_id: TITLE_BOOT.to_string(),
                body: vec![BodyLine::new(BODY_BOOT)],
                rows: Vec::new(),
                controls: Vec::new(),
                progress: None,
            },
            Stage::Welcome => self.welcome_screen(),
            Stage::ChooseBackup => self.choose_backup_screen(),
            Stage::ChooseKind => ScreenView {
                screen: ScreenId::ChooseKind,
                title_id: TITLE_CHOOSE_KIND.to_string(),
                body: vec![BodyLine::new(BODY_CHOOSE_KIND)],
                rows: Vec::new(),
                controls: vec![
                    Control::new(
                        "kind_files",
                        CONTROL_KIND_FILES,
                        ControlRole::Normal,
                        ShellAction::ChooseFiles,
                    ),
                    Control::new(
                        "kind_whole_pc",
                        CONTROL_KIND_WHOLE_PC,
                        ControlRole::Normal,
                        ShellAction::ChooseWholePc,
                    ),
                    Control::new(
                        "kind_rehearse",
                        CONTROL_KIND_REHEARSE,
                        ControlRole::Normal,
                        ShellAction::ChooseRehearse,
                    ),
                    Control::new("back", CONTROL_BACK, ControlRole::Cancel, ShellAction::Back),
                ],
                progress: None,
            },
            Stage::ChooseTarget => self.choose_target_screen(),
            Stage::OverrideConfirm { warning_id, .. } => ScreenView {
                screen: ScreenId::OverrideConfirm,
                title_id: TITLE_OVERRIDE.to_string(),
                body: vec![
                    BodyLine::new(BODY_OVERRIDE_INTRO),
                    BodyLine::new(warning_id),
                ],
                rows: Vec::new(),
                controls: vec![
                    Control::new(
                        "confirm_override",
                        CONTROL_CONFIRM_OVERRIDE,
                        ControlRole::Destructive,
                        ShellAction::ConfirmOverride,
                    ),
                    Control::new("back", CONTROL_BACK, ControlRole::Cancel, ShellAction::Back),
                ],
                progress: None,
            },
            Stage::PlanConfirm => self.plan_confirm_screen(),
            Stage::Running => ScreenView {
                screen: ScreenId::Progress,
                title_id: TITLE_PROGRESS.to_string(),
                body: vec![BodyLine::new(BODY_PROGRESS)],
                rows: Vec::new(),
                controls: vec![Control::new(
                    "cancel_job",
                    CONTROL_CANCEL_JOB,
                    ControlRole::Cancel,
                    ShellAction::CancelJob,
                )
                .disabled_if(self.job_id.is_none())],
                progress: self.progress.clone(),
            },
            Stage::Result {
                outcome,
                summary_id,
            } => {
                let mut body = vec![BodyLine::with_args(
                    match outcome {
                        JobOutcome::Succeeded => BODY_RESULT_SUCCEEDED,
                        JobOutcome::Failed => BODY_RESULT_FAILED,
                        JobOutcome::Cancelled => BODY_RESULT_CANCELLED,
                    },
                    vec![summary_id.clone()],
                )];
                if self.kind == Some(RestoreKind::WholePc) {
                    body.push(BodyLine::new(BODY_RESULT_VERIFY_NOTE));
                }
                ScreenView {
                    screen: ScreenId::Result,
                    title_id: TITLE_RESULT.to_string(),
                    body,
                    rows: Vec::new(),
                    controls: vec![
                        Control::new(
                            "to_welcome",
                            CONTROL_TO_WELCOME,
                            ControlRole::Default,
                            ShellAction::Back,
                        ),
                        Control::new("exit", CONTROL_EXIT, ControlRole::Normal, ShellAction::Exit),
                    ],
                    progress: None,
                }
            }
            Stage::PlanStale => ScreenView {
                screen: ScreenId::PlanStale,
                title_id: TITLE_STALE.to_string(),
                body: vec![BodyLine::new(BODY_STALE)],
                rows: Vec::new(),
                controls: vec![
                    Control::new(
                        "replan",
                        CONTROL_REPLAN,
                        ControlRole::Default,
                        ShellAction::Back,
                    ),
                    Control::new("exit", CONTROL_EXIT, ControlRole::Normal, ShellAction::Exit),
                ],
                progress: None,
            },
            Stage::Error {
                message_id,
                what_was_not_changed_id,
                ..
            } => ScreenView {
                screen: ScreenId::Error,
                title_id: TITLE_ERROR.to_string(),
                body: vec![
                    BodyLine::new(message_id),
                    BodyLine::with_args(
                        BODY_ERROR_WHAT_NOT_CHANGED,
                        vec![what_was_not_changed_id.clone()],
                    ),
                ],
                rows: Vec::new(),
                controls: vec![
                    Control::new("back", CONTROL_BACK, ControlRole::Cancel, ShellAction::Back),
                    Control::new("exit", CONTROL_EXIT, ControlRole::Normal, ShellAction::Exit),
                ],
                progress: None,
            },
            Stage::Exited => ScreenView {
                screen: ScreenId::Exit,
                title_id: TITLE_EXIT.to_string(),
                body: vec![BodyLine::new(BODY_EXIT)],
                rows: Vec::new(),
                controls: vec![Control::new(
                    "restart",
                    CONTROL_RESTART,
                    ControlRole::Default,
                    ShellAction::Restart,
                )],
                progress: None,
            },
        }
    }

    fn welcome_screen(&self) -> ScreenView {
        let mut body = vec![BodyLine::new(BODY_WELCOME)];
        match &self.config.media {
            Some(media) => {
                if media.intact {
                    body.push(BodyLine::new(BODY_MEDIA_OK));
                } else {
                    body.push(BodyLine::with_args(
                        BODY_MEDIA_PROBLEM,
                        vec![media.problem.clone().unwrap_or_default()],
                    ));
                }
                body.push(BodyLine::new(match media.boot_test {
                    BootTestFact::Tested => BODY_BOOT_TESTED,
                    BootTestFact::NotTested => BODY_BOOT_NOT_TESTED,
                    BootTestFact::Partial => BODY_BOOT_PARTIAL,
                    BootTestFact::Invalid => BODY_BOOT_INVALID,
                }));
            }
            None => body.push(BodyLine::new(BODY_MEDIA_UNCHECKED)),
        }
        match self.boot_marker {
            Some(true) => body.push(BodyLine::new(BODY_MARKER_RECORDED)),
            Some(false) => body.push(BodyLine::new(BODY_MARKER_FAILED)),
            None => {}
        }
        ScreenView {
            screen: ScreenId::Welcome,
            title_id: TITLE_WELCOME.to_string(),
            body,
            rows: Vec::new(),
            controls: vec![
                Control::new(
                    "continue",
                    CONTROL_CONTINUE,
                    ControlRole::Default,
                    ShellAction::Continue,
                ),
                Control::new("exit", CONTROL_EXIT, ControlRole::Normal, ShellAction::Exit),
            ],
            progress: None,
        }
    }

    fn choose_backup_screen(&self) -> ScreenView {
        let (body, rows) = match &self.backups {
            None => (vec![BodyLine::new(BODY_BACKUPS_LOADING)], Vec::new()),
            Some(list) if list.is_empty() => (vec![BodyLine::new(BODY_BACKUPS_EMPTY)], Vec::new()),
            Some(list) => (
                Vec::new(),
                list.iter()
                    .map(|b| ListRow {
                        id: b.backup_id.clone(),
                        text_id: BODY_BACKUP_ROW.to_string(),
                        args: vec![
                            b.label.clone(),
                            b.file_count.to_string(),
                            safereturn_core::format_bytes(b.total_bytes),
                        ],
                        selectable: true,
                        note_id: None,
                        note_is_refusal: false,
                    })
                    .collect(),
            ),
        };
        ScreenView {
            screen: ScreenId::ChooseBackup,
            title_id: TITLE_CHOOSE_BACKUP.to_string(),
            body,
            rows,
            // Rows are the picker's controls: the front-end
            // activates the highlighted row by feeding
            // ShellAction::SelectBackup with the row's id.
            controls: vec![Control::new(
                "back",
                CONTROL_BACK,
                ControlRole::Cancel,
                ShellAction::Back,
            )],
            progress: None,
        }
    }

    fn choose_target_screen(&self) -> ScreenView {
        let (mut body, rows) = match &self.disks {
            None => (vec![BodyLine::new(BODY_DISKS_LOADING)], Vec::new()),
            Some(list) if list.is_empty() => (vec![BodyLine::new(BODY_DISKS_EMPTY)], Vec::new()),
            Some(_) => (Vec::new(), self.target_rows()),
        };
        if self.awaiting_plan {
            body.push(BodyLine::new(BODY_PLANNING));
        }
        ScreenView {
            screen: ScreenId::ChooseTarget,
            title_id: TITLE_CHOOSE_TARGET.to_string(),
            body,
            rows,
            // Rows are the picker's controls, as on the backup
            // picker: activation is ShellAction::SelectTarget with
            // the row's id.
            controls: vec![Control::new(
                "back",
                CONTROL_BACK,
                ControlRole::Cancel,
                ShellAction::Back,
            )],
            progress: None,
        }
    }

    fn plan_confirm_screen(&self) -> ScreenView {
        let mut body = vec![BodyLine::new(BODY_CONFIRM_PLAN)];
        if let Some(summary) = &self.plan_target_summary {
            body.push(BodyLine::with_args(
                BODY_CONFIRM_TARGET,
                vec![summary.clone()],
            ));
        }
        body.push(BodyLine::with_args(
            BODY_CONFIRM_FILES,
            vec![
                self.plan_file_count.to_string(),
                safereturn_core::format_bytes(self.plan_total_bytes),
            ],
        ));
        // The erase warning is engine-owned copy, shown before the
        // confirm — part of the plan, never shell-invented.
        if let Some(id) = &self.plan_erase_warning_id {
            body.push(BodyLine::new(id));
        }
        for w in &self.plan_warnings {
            body.push(BodyLine::new(w));
        }
        ScreenView {
            screen: ScreenId::PlanConfirm,
            title_id: TITLE_CONFIRM.to_string(),
            body,
            rows: Vec::new(),
            controls: vec![
                Control::new(
                    "confirm_restore",
                    CONTROL_CONFIRM_RESTORE,
                    ControlRole::Destructive,
                    ShellAction::ConfirmPlan,
                ),
                Control::new(
                    "cancel",
                    CONTROL_CANCEL,
                    ControlRole::Cancel,
                    ShellAction::Back,
                ),
            ],
            progress: None,
        }
    }
}

trait DisabledIf {
    fn disabled_if(self, cond: bool) -> Self;
}

impl DisabledIf for Control {
    fn disabled_if(self, cond: bool) -> Self {
        if cond {
            self.disabled()
        } else {
            self
        }
    }
}
