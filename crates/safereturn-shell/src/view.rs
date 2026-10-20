//! The view types the front-end renders. Everything user-visible
//! is a strings-table id plus data args — a renderer never invents
//! wording, and a screen can be asserted on in tests without any
//! rendering at all.

use serde::{Deserialize, Serialize};

/// Which screen the view-model is showing. The front-end renders
/// exactly this screen; navigation lives entirely in the
/// view-model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenId {
    Boot,
    Welcome,
    ChooseBackup,
    ChooseKind,
    ChooseTarget,
    OverrideConfirm,
    PlanConfirm,
    Progress,
    Result,
    PlanStale,
    Error,
    Exit,
}

/// What pressing a control does. The front-end feeds the pressed
/// control's action back into `PeShellViewModel::on_action`; it
/// never interprets actions itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ShellAction {
    Continue,
    Back,
    Exit,
    Restart,
    SelectBackup {
        backup_id: String,
    },
    ChooseFiles,
    ChooseWholePc,
    ChooseRehearse,
    SelectTarget {
        disk_id: String,
    },
    ConfirmPlan,
    ConfirmOverride,
    CancelJob,
    /// Host report: the boot-test marker write the front-end
    /// attempted at shell start (S4 protocol) finished.
    BootMarkerWritten {
        ok: bool,
    },
}

/// Side effects only the host (front-end) can perform. The
/// view-model is pure — no file IO, no process control — so writing
/// the boot-test marker and leaving the shell are effects the
/// front-end executes and reports back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "effect", rename_all = "snake_case")]
pub enum ShellEffect {
    /// Write the S4 boot-test marker on the media's data partition
    /// via `safereturn_core::record_boot_test` (reached_shell =
    /// true — the shell is running, which is what the marker
    /// attests). Report the outcome with
    /// `ShellAction::BootMarkerWritten`.
    RecordBootTest { media_plan_id: String },
    /// The user explicitly confirmed a SafeTarget warning in the
    /// plan flow. The host's engine adapter adds the warning id to
    /// its SafeTargetContext acknowledgments before the re-issued
    /// plan request is handled, so the retry plans with the override
    /// recorded (S6 slice 1).
    AcknowledgeWarning { warning_id: String },
    /// Leave the shell (the front-end decides how: close the
    /// window; in WinPE the user then restarts via the Exit
    /// screen's guidance).
    ExitShell,
}

/// A control's role in its screen, for focus policy. On any screen
/// that can start something destructive, exactly one control is the
/// cancel and it — never the destructive control — is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlRole {
    /// Ordinary forward action.
    Normal,
    /// Proceeds with a job that changes nothing destructive
    /// (rehearsal) or navigates.
    Default,
    /// The screen's cancel/back — the default focus wherever a
    /// destructive control exists.
    Cancel,
    /// Starts the destructive step the screen is confirming.
    Destructive,
}

/// One control on a screen. All three naming ids are always
/// present: visible label, screen-reader accessible name, tooltip —
/// accessibility is a property of the model, not a renderer
/// afterthought.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Control {
    /// Stable control id within the flow (e.g. "confirm_restore").
    pub id: String,
    pub label_id: String,
    pub accessible_name_id: String,
    pub tooltip_id: String,
    pub enabled: bool,
    pub role: ControlRole,
    /// True when this control — not any destructive control — takes
    /// default focus. Set on the Cancel control of confirm screens.
    pub is_default_cancel: bool,
    pub action: ShellAction,
}

impl Control {
    pub fn new(id: &str, label_id: &str, role: ControlRole, action: ShellAction) -> Self {
        Self {
            id: id.to_string(),
            label_id: label_id.to_string(),
            accessible_name_id: crate::strings::accessible_name_id(label_id),
            tooltip_id: crate::strings::tooltip_id(label_id),
            enabled: true,
            role,
            is_default_cancel: role == ControlRole::Cancel,
            action,
        }
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// One line of body copy: a strings-table id plus its data args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyLine {
    pub id: String,
    pub args: Vec<String>,
}

impl BodyLine {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            args: Vec::new(),
        }
    }

    pub fn with_args(id: &str, args: Vec<String>) -> Self {
        Self {
            id: id.to_string(),
            args,
        }
    }
}

/// One selectable row in a picker screen (backups or disks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListRow {
    /// backup_id or disk_id — the value the select action carries.
    pub id: String,
    /// Body id used to render the row's main text, with `args`.
    pub text_id: String,
    pub args: Vec<String>,
    pub selectable: bool,
    /// Strings-table id explaining the row's state when it is not
    /// plainly selectable (a SafeTarget reason/warning id, or a
    /// shell note id); rendered with the row, never by color alone.
    pub note_id: Option<String>,
    /// True when the note is a refusal (the row can never be
    /// selected for this flow) rather than a warning.
    pub note_is_refusal: bool,
}

/// Job progress as the Progress screen renders it: the engine's
/// phase id (strings-table) plus raw counters — the renderer
/// formats numbers; the view-model invents no percentage the
/// engine did not send (total may be 0 = indeterminate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressView {
    pub phase_id: String,
    pub done: u64,
    pub total: u64,
    pub unit: String,
}

/// One screen, complete: what the front-end renders, nothing more
/// to decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScreenView {
    pub screen: ScreenId,
    pub title_id: String,
    pub body: Vec<BodyLine>,
    /// Picker rows; empty on non-picker screens.
    pub rows: Vec<ListRow>,
    pub controls: Vec<Control>,
    pub progress: Option<ProgressView>,
}
