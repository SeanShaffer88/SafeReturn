//! The strings table for the recovery shell (SHELL_CONTRACT §2.3:
//! one wording source — id → text, consumed by every shell; no
//! shell hardcodes copy anywhere else).
//!
//! The view-model and the front-end handle ONLY ids from this
//! module (plus ids owned by the contract/core: plan warnings,
//! phase ids, result summary ids, SafeTarget reason/warning ids).
//! The English text lives here and nowhere else in the shell
//! crates, so a wording change is a one-file change and the C#
//! desktop shell renders the same ids from the same table.
//!
//! `{0}`, `{1}`, … in a text are placeholders the renderer fills
//! from the body line's args, in order. Args are always data
//! (names, counts, sizes, ids) — never wording.

// -- Screen titles -----------------------------------------------------------

pub const TITLE_BOOT: &str = "shell.boot.title";
pub const TITLE_WELCOME: &str = "shell.welcome.title";
pub const TITLE_CHOOSE_BACKUP: &str = "shell.choose_backup.title";
pub const TITLE_CHOOSE_KIND: &str = "shell.choose_kind.title";
pub const TITLE_CHOOSE_TARGET: &str = "shell.choose_target.title";
pub const TITLE_OVERRIDE: &str = "shell.override.title";
pub const TITLE_CONFIRM: &str = "shell.confirm.title";
pub const TITLE_PROGRESS: &str = "shell.progress.title";
pub const TITLE_RESULT: &str = "shell.result.title";
pub const TITLE_STALE: &str = "shell.stale.title";
pub const TITLE_ERROR: &str = "shell.error.title";
pub const TITLE_EXIT: &str = "shell.exit.title";

// -- Body lines --------------------------------------------------------------

pub const BODY_BOOT: &str = "shell.boot.body";
pub const BODY_WELCOME: &str = "shell.welcome.body";
pub const BODY_MEDIA_OK: &str = "shell.media.ok";
pub const BODY_MEDIA_PROBLEM: &str = "shell.media.problem";
pub const BODY_MEDIA_UNCHECKED: &str = "shell.media.unchecked";
pub const BODY_BOOT_TESTED: &str = "shell.media.boot_tested";
pub const BODY_BOOT_NOT_TESTED: &str = "shell.media.boot_not_tested";
pub const BODY_BOOT_PARTIAL: &str = "shell.media.boot_partial";
pub const BODY_BOOT_INVALID: &str = "shell.media.boot_invalid";
pub const BODY_MARKER_RECORDED: &str = "shell.media.marker_recorded";
pub const BODY_MARKER_FAILED: &str = "shell.media.marker_failed";
pub const BODY_BACKUPS_LOADING: &str = "shell.backup.loading";
pub const BODY_BACKUPS_EMPTY: &str = "shell.backup.empty";
pub const BODY_BACKUP_ROW: &str = "shell.backup.row";
pub const BODY_CHOOSE_KIND: &str = "shell.choose_kind.body";
pub const BODY_DISKS_LOADING: &str = "shell.target.loading";
pub const BODY_DISKS_EMPTY: &str = "shell.target.empty";
pub const BODY_TARGET_ROW: &str = "shell.target.row";
pub const BODY_TARGET_REFUSED: &str = "shell.target.refused";
pub const BODY_TARGET_WARN: &str = "shell.target.warn";
pub const BODY_TARGET_NO_PATH: &str = "shell.target.no_path";
pub const BODY_PLANNING: &str = "shell.planning";
pub const BODY_CONFIRM_PLAN: &str = "shell.confirm.plan";
pub const BODY_CONFIRM_TARGET: &str = "shell.confirm.target";
pub const BODY_CONFIRM_FILES: &str = "shell.confirm.files";
pub const BODY_OVERRIDE_INTRO: &str = "shell.override.body";
pub const BODY_PROGRESS: &str = "shell.progress.body";
pub const BODY_RESULT_SUCCEEDED: &str = "shell.result.succeeded";
pub const BODY_RESULT_FAILED: &str = "shell.result.failed";
pub const BODY_RESULT_CANCELLED: &str = "shell.result.cancelled";
pub const BODY_RESULT_VERIFY_NOTE: &str = "shell.result.verify_note";
pub const BODY_STALE: &str = "shell.stale.body";
pub const BODY_ERROR_WHAT_NOT_CHANGED: &str = "shell.error.what_was_not_changed";
pub const BODY_INCOMPATIBLE: &str = "shell.error.incompatible";
pub const BODY_EXIT: &str = "shell.exit.body";

// -- Controls ----------------------------------------------------------------
// Every control has a label id, an accessible-name id, and a
// tooltip id. They are separate ids (not one shared string) so a
// screen reader name can be more explicit than the visible label
// without forking the wording by hand at call sites.

pub const CONTROL_CONTINUE: &str = "shell.control.continue";
pub const CONTROL_BACK: &str = "shell.control.back";
pub const CONTROL_EXIT: &str = "shell.control.exit";
pub const CONTROL_SELECT_BACKUP: &str = "shell.control.select_backup";
pub const CONTROL_KIND_FILES: &str = "shell.control.kind_files";
pub const CONTROL_KIND_WHOLE_PC: &str = "shell.control.kind_whole_pc";
pub const CONTROL_KIND_REHEARSE: &str = "shell.control.kind_rehearse";
pub const CONTROL_SELECT_TARGET: &str = "shell.control.select_target";
pub const CONTROL_CONFIRM_RESTORE: &str = "shell.control.confirm_restore";
pub const CONTROL_CONFIRM_OVERRIDE: &str = "shell.control.confirm_override";
pub const CONTROL_CANCEL: &str = "shell.control.cancel";
pub const CONTROL_CANCEL_JOB: &str = "shell.control.cancel_job";
pub const CONTROL_REPLAN: &str = "shell.control.replan";
pub const CONTROL_TO_WELCOME: &str = "shell.control.to_welcome";
pub const CONTROL_RESTART: &str = "shell.control.restart";

pub fn accessible_name_id(label_id: &str) -> String {
    format!("{label_id}.name")
}

pub fn tooltip_id(label_id: &str) -> String {
    format!("{label_id}.tip")
}

/// Every id this module defines, for the table-completeness test
/// and for export to the other shells.
pub const ALL_IDS: &[&str] = &[
    TITLE_BOOT,
    TITLE_WELCOME,
    TITLE_CHOOSE_BACKUP,
    TITLE_CHOOSE_KIND,
    TITLE_CHOOSE_TARGET,
    TITLE_OVERRIDE,
    TITLE_CONFIRM,
    TITLE_PROGRESS,
    TITLE_RESULT,
    TITLE_STALE,
    TITLE_ERROR,
    TITLE_EXIT,
    BODY_BOOT,
    BODY_WELCOME,
    BODY_MEDIA_OK,
    BODY_MEDIA_PROBLEM,
    BODY_MEDIA_UNCHECKED,
    BODY_BOOT_TESTED,
    BODY_BOOT_NOT_TESTED,
    BODY_BOOT_PARTIAL,
    BODY_BOOT_INVALID,
    BODY_MARKER_RECORDED,
    BODY_MARKER_FAILED,
    BODY_BACKUPS_LOADING,
    BODY_BACKUPS_EMPTY,
    BODY_BACKUP_ROW,
    BODY_CHOOSE_KIND,
    BODY_DISKS_LOADING,
    BODY_DISKS_EMPTY,
    BODY_TARGET_ROW,
    BODY_TARGET_REFUSED,
    BODY_TARGET_WARN,
    BODY_TARGET_NO_PATH,
    BODY_PLANNING,
    BODY_CONFIRM_PLAN,
    BODY_CONFIRM_TARGET,
    BODY_CONFIRM_FILES,
    BODY_OVERRIDE_INTRO,
    BODY_PROGRESS,
    BODY_RESULT_SUCCEEDED,
    BODY_RESULT_FAILED,
    BODY_RESULT_CANCELLED,
    BODY_RESULT_VERIFY_NOTE,
    BODY_STALE,
    BODY_ERROR_WHAT_NOT_CHANGED,
    BODY_INCOMPATIBLE,
    BODY_EXIT,
    CONTROL_CONTINUE,
    CONTROL_BACK,
    CONTROL_EXIT,
    CONTROL_SELECT_BACKUP,
    CONTROL_KIND_FILES,
    CONTROL_KIND_WHOLE_PC,
    CONTROL_KIND_REHEARSE,
    CONTROL_SELECT_TARGET,
    CONTROL_CONFIRM_RESTORE,
    CONTROL_CONFIRM_OVERRIDE,
    CONTROL_CANCEL,
    CONTROL_CANCEL_JOB,
    CONTROL_REPLAN,
    CONTROL_TO_WELCOME,
    CONTROL_RESTART,
];

/// The English text for an id in this table; `None` for ids owned
/// by other modules (contract/core ids) or unknown ids. Renderers
/// fall back to the id itself only in diagnostics — a missing text
/// is a bug the completeness test exists to catch.
pub fn text(id: &str) -> Option<&'static str> {
    Some(match id {
        TITLE_BOOT => "SafeReturn Recovery",
        TITLE_WELCOME => "SafeReturn Recovery",
        TITLE_CHOOSE_BACKUP => "Choose a backup",
        TITLE_CHOOSE_KIND => "What do you want to do?",
        TITLE_CHOOSE_TARGET => "Choose where to restore",
        TITLE_OVERRIDE => "One more check before continuing",
        TITLE_CONFIRM => "Check this carefully before restoring",
        TITLE_PROGRESS => "Working…",
        TITLE_RESULT => "Result",
        TITLE_STALE => "The plan no longer matches",
        TITLE_ERROR => "Something went wrong",
        TITLE_EXIT => "You can leave recovery now",

        BODY_BOOT => "Starting SafeReturn Recovery…",
        BODY_WELCOME => "This tool restores files — or the whole PC — from a SafeReturn backup. Nothing is changed until you confirm a restore plan.",
        BODY_MEDIA_OK => "The recovery media checked out: its files match what was written when it was created.",
        BODY_MEDIA_PROBLEM => "The recovery media check found a problem ({0}). You can still try to restore, but if it fails, rebuild the recovery media on a working PC.",
        BODY_MEDIA_UNCHECKED => "The recovery media could not be checked this time. You can continue, but SafeReturn cannot vouch for this media.",
        BODY_BOOT_TESTED => "This recovery media has been boot-tested before, and the recovery shell opened.",
        BODY_BOOT_NOT_TESTED => "This recovery media has not completed a recorded boot test before now.",
        BODY_BOOT_PARTIAL => "A previous boot of this media started but did not reach the recovery shell.",
        BODY_BOOT_INVALID => "This media's boot-test record is not valid data and was ignored.",
        BODY_MARKER_RECORDED => "This boot was recorded on the media, so the media now counts as boot-tested.",
        BODY_MARKER_FAILED => "SafeReturn could not record this boot on the media. The restore can continue; the media's boot test stays unrecorded.",
        BODY_BACKUPS_LOADING => "Looking for backups…",
        BODY_BACKUPS_EMPTY => "No backups were found on the opened backup drive. Check the drive is plugged in, then go back and try again.",
        BODY_BACKUP_ROW => "{0} — {1} files, {2}",
        BODY_CHOOSE_KIND => "Restore individual files, restore the whole PC from this backup, or rehearse: restore sample files to a test area and check them, changing nothing on this PC.",
        BODY_DISKS_LOADING => "Looking for disks…",
        BODY_DISKS_EMPTY => "No disks were found. Check the drive cables, then go back and try again.",
        BODY_TARGET_ROW => "{0} (…{1}) — {2}",
        BODY_TARGET_REFUSED => "Cannot be used: {0}",
        BODY_TARGET_WARN => "Warning: {0}",
        BODY_TARGET_NO_PATH => "Files cannot be restored here because this disk has no folder SafeReturn can write to in recovery.",
        BODY_PLANNING => "Asking the engine to plan this restore… nothing is erased by planning.",
        BODY_CONFIRM_PLAN => "The engine planned this restore. Read it, then confirm — confirming is what starts the restore.",
        BODY_CONFIRM_TARGET => "Target: {0}",
        BODY_CONFIRM_FILES => "{0} files, {1} to restore",
        BODY_OVERRIDE_INTRO => "The engine will only plan this target if you confirm the warning below. The confirmation is recorded in the plan.",
        BODY_PROGRESS => "Keep this PC plugged in. You can cancel, but a whole-PC restore that is cancelled part-way leaves the target disk partly written.",
        BODY_RESULT_SUCCEEDED => "Finished: {0}",
        BODY_RESULT_FAILED => "The job did not finish: {0}",
        BODY_RESULT_CANCELLED => "The job was cancelled: {0}",
        BODY_RESULT_VERIFY_NOTE => "A restore is only counted as good when its files verify. Whether the restored PC actually boots can only be proven by starting it — SafeReturn never claims a boot it did not see.",
        BODY_STALE => "The disk changed after the plan was made, so the engine refused to run it — nothing was erased or written. Make a new plan for the disk as it is now.",
        BODY_ERROR_WHAT_NOT_CHANGED => "What was not changed: {0}",
        BODY_INCOMPATIBLE => "This recovery shell and the engine do not match. SafeReturn needs to be repaired or reinstalled; nothing was changed.",
        BODY_EXIT => "You can remove the recovery media and restart the PC. If you restored the whole PC, the restored Windows should start; if it does not, boot this media again and check the restore result.",

        CONTROL_CONTINUE => "Continue",
        "shell.control.continue.name" => "Continue to choosing a backup",
        "shell.control.continue.tip" => "Go to the list of backups on the backup drive",
        CONTROL_BACK => "Back",
        "shell.control.back.name" => "Go back one step",
        "shell.control.back.tip" => "Return to the previous step without changing anything",
        CONTROL_EXIT => "Exit recovery",
        "shell.control.exit.name" => "Exit SafeReturn Recovery",
        "shell.control.exit.tip" => "Leave recovery without restoring anything else",
        CONTROL_SELECT_BACKUP => "Use this backup",
        "shell.control.select_backup.name" => "Use the highlighted backup",
        "shell.control.select_backup.tip" => "Choose what to do with this backup next",
        CONTROL_KIND_FILES => "Restore files",
        "shell.control.kind_files.name" => "Restore files from this backup",
        "shell.control.kind_files.tip" => "Restore the backup's files into a folder on a disk you pick",
        CONTROL_KIND_WHOLE_PC => "Restore the whole PC",
        "shell.control.kind_whole_pc.name" => "Restore the whole PC from this backup",
        "shell.control.kind_whole_pc.tip" => "Rebuild this PC from the backup — this erases the target disk completely",
        CONTROL_KIND_REHEARSE => "Rehearse restoring files",
        "shell.control.kind_rehearse.name" => "Rehearse restoring files from this backup",
        "shell.control.kind_rehearse.tip" => "Test-restore sample files and check them, changing nothing on this PC",
        CONTROL_SELECT_TARGET => "Use this disk",
        "shell.control.select_target.name" => "Use the highlighted disk as the target",
        "shell.control.select_target.tip" => "Ask the engine to plan the restore onto this disk — planning erases nothing",
        CONTROL_CONFIRM_RESTORE => "Restore now",
        "shell.control.confirm_restore.name" => "Start the restore exactly as planned",
        "shell.control.confirm_restore.tip" => "This starts the restore. A whole-PC restore erases the target disk completely",
        CONTROL_CONFIRM_OVERRIDE => "I understand — plan anyway",
        "shell.control.confirm_override.name" => "Confirm the warning and plan this target anyway",
        "shell.control.confirm_override.tip" => "Your confirmation is recorded in the plan before anything is erased",
        CONTROL_CANCEL => "Cancel",
        "shell.control.cancel.name" => "Cancel and go back",
        "shell.control.cancel.tip" => "Do not restore; go back without changing anything",
        CONTROL_CANCEL_JOB => "Cancel the job",
        "shell.control.cancel_job.name" => "Cancel the running job",
        "shell.control.cancel_job.tip" => "Ask the engine to stop. A part-written target disk is not bootable",
        CONTROL_REPLAN => "Make a new plan",
        "shell.control.replan.name" => "Go back and make a new plan",
        "shell.control.replan.tip" => "Return to choosing a target disk for a fresh plan",
        CONTROL_TO_WELCOME => "Back to the start",
        "shell.control.to_welcome.name" => "Back to the start screen",
        "shell.control.to_welcome.tip" => "Return to the first screen",
        CONTROL_RESTART => "Restart the PC",
        "shell.control.restart.name" => "Restart the PC now",
        "shell.control.restart.tip" => "Leave recovery and restart — remove the recovery media first",
        _ => return None,
    })
}
