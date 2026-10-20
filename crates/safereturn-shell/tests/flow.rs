//! S6 slice 2: the PE shell view-model, driven end-to-end with
//! scripted engine events. These tests are the flow's contract:
//! screen sequences, the requests each step emits, SafeTarget
//! verdicts rendered on the target picker, destructive confirms
//! defaulting to Cancel, and the failure paths (bad backup,
//! refused target, override demand, plan-stale mid-flow, failed
//! job) landing on screens with a way back.

use safereturn_contract::{BackupSummary, DiskInfo, Event, JobOutcome, Request, SystemRestorePlan};
use safereturn_core::{DiskIdentity, SafeTargetContext};
use safereturn_shell::strings;
use safereturn_shell::view::{ControlRole, ScreenId, ShellAction, ShellEffect};
use safereturn_shell::{MediaCheckFacts, PeShellViewModel, ShellConfig};

const GIB: u64 = 1024 * 1024 * 1024;

fn disk(id: &str, model: &str, serial: &str, size: u64, removable: bool) -> DiskInfo {
    DiskInfo {
        disk_id: id.to_string(),
        model: model.to_string(),
        serial_suffix: serial.to_string(),
        size_bytes: size,
        free_bytes: size / 2,
        is_system_disk: false,
        is_removable: removable,
        warnings: Vec::new(),
    }
}

fn config() -> ShellConfig {
    ShellConfig {
        shell_version: "test".to_string(),
        media: Some(MediaCheckFacts {
            plan_id: "plan-media-1".to_string(),
            intact: true,
            problem: None,
            boot_test: safereturn_shell::BootTestFact::NotTested,
        }),
        safe_target: SafeTargetContext {
            // The backup lives on disk-2; the media booted from disk-3.
            backup_disk: Some(DiskIdentity::of(
                "disk-2",
                "WD Elements",
                "5555",
                2 * 1024 * GIB,
            )),
            media_disk: Some(DiskIdentity::of("disk-3", "USB Flash", "X7K2", 64 * GIB)),
            ..Default::default()
        },
        media_disk_id: Some("disk-3".to_string()),
        file_restore_dirs: vec![
            ("disk-1".to_string(), "D:\\SafeReturn-Restored".to_string()),
            ("disk-2".to_string(), "E:\\SafeReturn-Restored".to_string()),
        ],
    }
}

fn backups() -> Vec<BackupSummary> {
    vec![
        BackupSummary {
            backup_id: "set-system".to_string(),
            label: "System backup".to_string(),
            created_unix: 1_700_003_000,
            file_count: 6,
            total_bytes: 1234,
        },
        BackupSummary {
            backup_id: "set-files".to_string(),
            label: "File backup".to_string(),
            created_unix: 1_700_004_000,
            file_count: 3,
            total_bytes: 99,
        },
    ]
}

fn disks() -> Vec<DiskInfo> {
    vec![
        disk("disk-1", "Samsung SSD 990", "1234", 256 * GIB, false),
        disk("disk-2", "WD Elements", "5555", 2 * 1024 * GIB, true),
        disk("disk-3", "USB Flash", "X7K2", 64 * GIB, true),
    ]
}

/// A view-model past Hello/Welcome with both lists delivered.
fn at_choose_kind(vm: &mut PeShellViewModel) {
    let reqs = vm.start();
    assert!(matches!(reqs.as_slice(), [Request::Hello { .. }]));
    let reqs = vm.on_event(Event::Welcome {
        contract_version: 1,
        engine_version: "test".to_string(),
    });
    assert_eq!(reqs, vec![Request::ListBackups, Request::ListDisks]);
    vm.on_event(Event::BackupList { backups: backups() });
    vm.on_event(Event::DiskList { disks: disks() });
    vm.on_action(ShellAction::Continue);
    assert_eq!(vm.screen().screen, ScreenId::ChooseBackup);
    vm.on_action(ShellAction::SelectBackup {
        backup_id: "set-system".to_string(),
    });
    assert_eq!(vm.screen().screen, ScreenId::ChooseKind);
}

fn system_planned() -> Event {
    Event::SystemRestorePlanned(SystemRestorePlan {
        plan_token: "tok-1".to_string(),
        backup_id: "set-system".to_string(),
        target_disk_id: "disk-1".to_string(),
        target_summary: "Samsung SSD 990 (…1234): 256 GiB disk".to_string(),
        erase_warning_id: Some("system_restore.will_erase_target".to_string()),
        firmware: "uefi".to_string(),
        partition_count: 4,
        file_count: 7,
        total_bytes: 4096,
        warnings: vec!["system_restore.bitlocker_not_restored".to_string()],
    })
}

// ------------------------------------------------------------ happy paths

#[test]
fn whole_pc_flow_end_to_end() {
    let mut vm = PeShellViewModel::new(config());
    // The boot-test marker is requested at start (S4 protocol).
    vm.start();
    let effects = vm.take_effects();
    assert!(effects.contains(&ShellEffect::RecordBootTest {
        media_plan_id: "plan-media-1".to_string()
    }));
    vm.on_event(Event::Welcome {
        contract_version: 1,
        engine_version: "test".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Welcome);
    // Media intact + not-yet-tested are separate body facts.
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_MEDIA_OK));
    assert!(ids.contains(&strings::BODY_BOOT_NOT_TESTED));

    vm.on_event(Event::BackupList { backups: backups() });
    vm.on_event(Event::DiskList { disks: disks() });
    vm.on_action(ShellAction::Continue);
    vm.on_action(ShellAction::SelectBackup {
        backup_id: "set-system".to_string(),
    });
    vm.on_action(ShellAction::ChooseWholePc);
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::ChooseTarget);
    // disk-2 is the backup disk: refused. disk-3 is the media disk:
    // refused. disk-1 is internal (non-removable warn) but selectable.
    let row = |id: &str| s.rows.iter().find(|r| r.id == id).unwrap().clone();
    assert!(!row("disk-2").selectable && row("disk-2").note_is_refusal);
    assert_eq!(
        row("disk-2").note_id.as_deref(),
        Some("target.is_backup_disk")
    );
    assert!(!row("disk-3").selectable);
    assert_eq!(
        row("disk-3").note_id.as_deref(),
        Some("target.is_media_disk")
    );
    assert!(row("disk-1").selectable);
    assert_eq!(
        row("disk-1").note_id.as_deref(),
        Some("target.non_removable")
    );

    // Selecting a refused row emits nothing, even if asked directly.
    let reqs = vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-2".to_string(),
    });
    assert!(reqs.is_empty());
    assert_eq!(vm.screen().screen, ScreenId::ChooseTarget);

    let reqs = vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-1".to_string(),
    });
    assert_eq!(
        reqs,
        vec![Request::PlanSystemRestore {
            backup_id: "set-system".to_string(),
            target_disk_id: "disk-1".to_string()
        }]
    );

    vm.on_event(system_planned());
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::PlanConfirm);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    // The engine's erase warning and plan warnings are on the
    // confirm screen — before the confirm, not after.
    assert!(ids.contains(&"system_restore.will_erase_target"));
    assert!(ids.contains(&"system_restore.bitlocker_not_restored"));
    // The destructive confirm is NOT the default; Cancel is.
    let confirm = s
        .controls
        .iter()
        .find(|c| c.id == "confirm_restore")
        .unwrap();
    assert_eq!(confirm.role, ControlRole::Destructive);
    assert!(!confirm.is_default_cancel);
    let cancel = s.controls.iter().find(|c| c.id == "cancel").unwrap();
    assert!(cancel.is_default_cancel);
    // Every control carries label + accessible name + tooltip ids,
    // and every one of those ids has text in the strings table.
    for c in &s.controls {
        assert!(strings::text(&c.label_id).is_some(), "label {}", c.label_id);
        assert!(
            strings::text(&c.accessible_name_id).is_some(),
            "name {}",
            c.accessible_name_id
        );
        assert!(
            strings::text(&c.tooltip_id).is_some(),
            "tip {}",
            c.tooltip_id
        );
    }

    let reqs = vm.on_action(ShellAction::ConfirmPlan);
    assert_eq!(
        reqs,
        vec![Request::StartSystemRestore {
            plan_token: "tok-1".to_string()
        }]
    );
    vm.on_event(Event::JobStarted {
        job_id: "job-1".to_string(),
    });
    vm.on_event(Event::JobProgress {
        job_id: "job-1".to_string(),
        phase_id: "phase.restoring_system".to_string(),
        done: 3,
        total: 7,
        unit: "files".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Progress);
    let p = s.progress.unwrap();
    assert_eq!((p.done, p.total, p.unit.as_str()), (3, 7, "files"));

    vm.on_event(Event::JobFinished {
        job_id: "job-1".to_string(),
        outcome: JobOutcome::Succeeded,
        summary_id: "result.system_restore_completed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Result);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_RESULT_SUCCEEDED));
    // Whole-PC results carry the files-vs-boot honesty note.
    assert!(ids.contains(&strings::BODY_RESULT_VERIFY_NOTE));
}

#[test]
fn file_restore_flow_uses_the_hosts_restore_dir() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    vm.on_action(ShellAction::ChooseFiles);
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::ChooseTarget);
    // For files, the media disk is disabled (RAM disk), the backup
    // disk is selectable (restoring files erases nothing).
    let row = |id: &str| s.rows.iter().find(|r| r.id == id).unwrap().clone();
    assert!(!row("disk-3").selectable);
    assert!(row("disk-2").selectable);
    assert!(row("disk-1").selectable);

    let reqs = vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-1".to_string(),
    });
    assert_eq!(
        reqs,
        vec![Request::PlanRestore {
            backup_id: "set-system".to_string(),
            target_dir: "D:\\SafeReturn-Restored".to_string(),
            path: None
        }]
    );
    vm.on_event(Event::RestorePlanned(safereturn_contract::RestorePlan {
        plan_token: "tok-f".to_string(),
        backup_id: "set-system".to_string(),
        target_summary: "6 files to D:\\SafeReturn-Restored".to_string(),
        erase_warning_id: None,
        file_count: 6,
        total_bytes: 1234,
        overwrite_count: 0,
    }));
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::PlanConfirm);
    let reqs = vm.on_action(ShellAction::ConfirmPlan);
    assert_eq!(
        reqs,
        vec![Request::StartRestore {
            plan_token: "tok-f".to_string()
        }]
    );
}

#[test]
fn rehearsal_goes_straight_to_progress_without_a_plan() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    let reqs = vm.on_action(ShellAction::ChooseRehearse);
    assert_eq!(
        reqs,
        vec![Request::StartFileRehearsal {
            backup_id: "set-system".to_string(),
            paths: Vec::new()
        }]
    );
    assert_eq!(vm.screen().screen, ScreenId::Progress);
    vm.on_event(Event::JobFinished {
        job_id: "job-9".to_string(),
        outcome: JobOutcome::Succeeded,
        summary_id: "result.file_rehearsal_passed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Result);
    // The boot honesty note belongs to whole-PC restores only.
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(!ids.contains(&strings::BODY_RESULT_VERIFY_NOTE));
}

// ------------------------------------------------------------ failure paths

#[test]
fn bad_backup_lands_on_the_error_screen_with_a_way_back() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    vm.on_action(ShellAction::ChooseWholePc);
    vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-1".to_string(),
    });
    vm.on_event(Event::Error {
        code: "system_restore.not_a_system_set".to_string(),
        message_id: "system_restore.not_a_system_set".to_string(),
        what_was_not_changed_id: "shell.error.nothing_changed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Error);
    assert_eq!(
        vm.current_error_code(),
        Some("system_restore.not_a_system_set")
    );
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&"system_restore.not_a_system_set"));
    assert!(ids.contains(&strings::BODY_ERROR_WHAT_NOT_CHANGED));
    // Back returns to the target pick (the flow's context survives).
    vm.on_action(ShellAction::Back);
    assert_eq!(vm.screen().screen, ScreenId::ChooseTarget);
}

#[test]
fn override_demand_gets_its_own_screen_and_retries_the_plan() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    vm.on_action(ShellAction::ChooseWholePc);
    vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-1".to_string(),
    });
    vm.on_event(Event::Error {
        code: "target.override_required".to_string(),
        message_id: "target.non_removable".to_string(),
        what_was_not_changed_id: "shell.error.nothing_changed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::OverrideConfirm);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&"target.non_removable"));
    // The override confirm is destructive-role; Back/Cancel is default.
    let confirm = s
        .controls
        .iter()
        .find(|c| c.id == "confirm_override")
        .unwrap();
    assert!(!confirm.is_default_cancel);
    assert!(
        s.controls
            .iter()
            .find(|c| c.id == "back")
            .unwrap()
            .is_default_cancel
    );

    let reqs = vm.on_action(ShellAction::ConfirmOverride);
    // The host is told to record the acknowledgment, and the plan
    // request is re-issued for the same disk.
    let effects = vm.take_effects();
    assert!(effects.contains(&ShellEffect::AcknowledgeWarning {
        warning_id: "target.non_removable".to_string()
    }));
    assert_eq!(
        reqs,
        vec![Request::PlanSystemRestore {
            backup_id: "set-system".to_string(),
            target_disk_id: "disk-1".to_string()
        }]
    );
    vm.on_event(system_planned());
    assert_eq!(vm.screen().screen, ScreenId::PlanConfirm);
}

#[test]
fn plan_stale_mid_flow_gets_the_stale_screen_not_a_generic_error() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    vm.on_action(ShellAction::ChooseWholePc);
    vm.on_action(ShellAction::SelectTarget {
        disk_id: "disk-1".to_string(),
    });
    vm.on_event(system_planned());
    vm.on_action(ShellAction::ConfirmPlan);
    // The disk changed between plan and execute: the engine
    // refuses before starting the job.
    vm.on_event(Event::Error {
        code: "system_restore.plan_stale".to_string(),
        message_id: "system_restore.plan_stale".to_string(),
        what_was_not_changed_id: "shell.error.nothing_changed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::PlanStale);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_STALE));
    vm.on_action(ShellAction::Back);
    assert_eq!(vm.screen().screen, ScreenId::ChooseTarget);
}

#[test]
fn failed_job_reports_failed_and_a_late_error_does_not_hijack_the_result() {
    let mut vm = PeShellViewModel::new(config());
    at_choose_kind(&mut vm);
    vm.on_action(ShellAction::ChooseRehearse);
    vm.on_event(Event::JobFinished {
        job_id: "job-2".to_string(),
        outcome: JobOutcome::Failed,
        summary_id: "result.file_rehearsal_failed".to_string(),
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Result);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_RESULT_FAILED));
    // Engine flows may surface the causing error after JobFinished;
    // the result screen stays.
    vm.on_event(Event::Error {
        code: "chunk.corrupt".to_string(),
        message_id: "chunk.corrupt".to_string(),
        what_was_not_changed_id: "shell.error.nothing_changed".to_string(),
    });
    assert_eq!(vm.screen().screen, ScreenId::Result);
}

#[test]
fn media_problem_and_marker_failure_are_shown_not_hidden() {
    let mut cfg = config();
    cfg.media = Some(MediaCheckFacts {
        plan_id: "plan-media-1".to_string(),
        intact: false,
        problem: Some("safereturn/app.exe: content differs".to_string()),
        boot_test: safereturn_shell::BootTestFact::Invalid,
    });
    let mut vm = PeShellViewModel::new(cfg);
    vm.start();
    vm.on_event(Event::Welcome {
        contract_version: 1,
        engine_version: "test".to_string(),
    });
    vm.on_action(ShellAction::BootMarkerWritten { ok: false });
    let s = vm.screen();
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_MEDIA_PROBLEM));
    assert!(ids.contains(&strings::BODY_BOOT_INVALID));
    assert!(ids.contains(&strings::BODY_MARKER_FAILED));
    // Continue is still offered — a sick stick does not strand the
    // user away from a backup that may live elsewhere.
    assert!(
        s.controls
            .iter()
            .find(|c| c.id == "continue")
            .unwrap()
            .enabled
    );
}

#[test]
fn incompatible_engine_is_a_repair_message_not_a_version_error() {
    let mut vm = PeShellViewModel::new(config());
    vm.start();
    vm.on_event(Event::Incompatible {
        minimum_contract_version: 2,
    });
    let s = vm.screen();
    assert_eq!(s.screen, ScreenId::Error);
    let ids: Vec<&str> = s.body.iter().map(|b| b.id.as_str()).collect();
    assert!(ids.contains(&strings::BODY_INCOMPATIBLE));
}

#[test]
fn strings_table_is_complete_and_unique() {
    let mut seen = std::collections::HashSet::new();
    for id in strings::ALL_IDS {
        assert!(seen.insert(id), "duplicate id {id}");
        assert!(strings::text(id).is_some(), "no text for {id}");
        // Every control's derived name/tooltip ids resolve too.
        if id.starts_with("shell.control.") {
            assert!(
                strings::text(&strings::accessible_name_id(id)).is_some(),
                "no accessible name for {id}"
            );
            assert!(
                strings::text(&strings::tooltip_id(id)).is_some(),
                "no tooltip for {id}"
            );
        }
    }
}
