//! S6 slice 4: Level-3 Boot Rehearsal.
//! - A full run on a real encrypted system set: files applied to
//!   staging through the production restore path, verified per
//!   partition, record written — and the report still says
//!   "not boot-tested", with boot_registered an unknown Fact.
//! - A corrupted chunk: the rehearsal fails at verification with
//!   the affected partition named, not with a bare error.
//! - The checklists: Hyper-V steps as data (commands built from
//!   the plan) vs. the Home validation-only path.
//! - The record protocol: only record_vm_boot_outcome (with a
//!   source) may move vm_boot away from NotBootTested.

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::boot_rehearsal::*;
use safereturn_core::system::{BcdCapture, BitLockerState, BootMode, Fact, SystemFacts, WinReInfo};
use safereturn_core::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const GIB: u64 = 1024 * 1024 * 1024;
static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_base(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base =
        std::env::temp_dir().join(format!("safereturn-s6-l3-{tag}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base
}

fn write(path: &PathBuf, content: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn engine_with_system_set(tag: &str) -> (Engine, PathBuf, String) {
    let base = tmp_base(tag);
    let os_src = base.join("src").join("osroot");
    let esp_src = base.join("src").join("esproot");
    write(&os_src.join("Windows/explorer.exe"), b"explorer-bytes");
    write(
        &os_src.join("Windows/System32/Recovery/Winre.wim"),
        b"winre-image-bytes",
    );
    write(&os_src.join("Users/Sean/notes.txt"), b"hello rehearsal");
    write(&esp_src.join("EFI/Boot/bootx64.efi"), b"bootx64");
    write(
        &esp_src.join("EFI/Microsoft/Boot/bootmgfw.efi"),
        b"bootmgfw",
    );

    let (locked, _) = Volume::create(base.join("volume"), "pw", 1_700_003_000).unwrap();
    let volume = locked.unlock_with_passphrase("pw").unwrap();
    let outcome = backup_tree(
        &volume,
        "System backup",
        &[os_src.clone(), esp_src.clone()],
        1_700_003_000,
        &mut |_, _| {},
    )
    .unwrap();
    let set_id = outcome.manifest.set_id.clone();
    let esp_listing = list_esp_files(&esp_src).unwrap();
    let mut bitlocker = BTreeMap::new();
    bitlocker.insert(
        "C:".to_string(),
        Fact::known(BitLockerState::On, "test bitlocker query"),
    );
    attach_system_facts(
        &volume,
        &set_id,
        SystemFacts {
            format_version: 1,
            gathered_unix: 1_700_003_000,
            boot_mode: Fact::known(BootMode::Uefi, "test firmware query"),
            secure_boot: Fact::known(true, "test secure boot query"),
            bitlocker,
            esp_files: Fact::known(esp_listing, "test esp listing"),
            winre: Fact::known(
                WinReInfo {
                    present: true,
                    location: Some("C:\\Windows\\System32\\Recovery\\Winre.wim".to_string()),
                },
                "test winre query",
            ),
            bcd: BcdCapture::not_included("test", "BCD is rebuilt by bcdboot during restore"),
        },
    )
    .unwrap();
    (Engine::new(volume), base, set_id)
}

fn target() -> SystemRestoreTargetFacts {
    SystemRestoreTargetFacts {
        disk_id: "disk-1".to_string(),
        model: "Samsung SSD 990".to_string(),
        serial_suffix: "1234".to_string(),
        size_bytes: 256 * GIB,
        removable: false,
        firmware: Fact::known(BootMode::Uefi, "test firmware query"),
    }
}

fn options() -> SystemRestoreOptions {
    SystemRestoreOptions {
        os_root: "osroot".to_string(),
        esp_root: "esproot".to_string(),
    }
}

#[test]
fn full_run_verifies_files_and_still_says_not_boot_tested() {
    let (mut engine, base, set_id) = engine_with_system_set("run");
    let staging = base.join("staging");
    let vm = VmFacts {
        hyperv_available: true,
        edition: Some("Windows 11 Pro".to_string()),
    };
    let mut events: Vec<Event> = Vec::new();
    let report = engine
        .run_boot_rehearsal(
            &set_id,
            &target(),
            &options(),
            &staging,
            Some(&vm),
            &mut |e| events.push(e),
        )
        .unwrap();

    assert!(report.files_verified, "report: {report:?}");
    assert!(report.layout_valid, "layout: {}", report.layout_detail);
    assert!(report.passed());
    assert!(report.application_error.is_none());
    assert!(report.partitions.iter().all(|p| p.passed()));
    // Files really landed, byte-identical.
    assert_eq!(
        fs::read(staging.join("windows/Windows/explorer.exe")).unwrap(),
        b"explorer-bytes"
    );
    assert_eq!(
        fs::read(staging.join("winre/Recovery/WindowsRE/Winre.wim")).unwrap(),
        b"winre-image-bytes"
    );
    // The four facts stay separate.
    assert_eq!(report.vm_boot, VmBootStatus::NotBootTested);
    assert!(report.boot_registered.value.is_none());
    assert!(report
        .boot_registered
        .unknown_reason
        .as_deref()
        .unwrap()
        .contains("bcdboot"));
    // The verdict line carries the exact not-boot-tested wording.
    assert!(report.verdict_line().contains(NOT_BOOT_TESTED_LINE));
    assert!(report.verdict_line().contains("files verified"));
    // Job finished as a success under the rehearsal summary id.
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Succeeded,
            summary_id,
            ..
        }) if summary_id == "result.boot_rehearsal_files_verified"
    ));
    // The record file is in the staging dir and reads back equal.
    let read_back = read_rehearsal_record(&staging).unwrap();
    assert_eq!(read_back.plan_id, report.plan_id);
    assert_eq!(read_back.vm_boot, VmBootStatus::NotBootTested);
    // Plan warnings rode along (BitLocker was on for C:).
    assert!(report
        .warnings
        .contains(&"system_restore.bitlocker_not_restored".to_string()));
}

#[test]
fn corrupt_chunk_fails_at_verify_with_the_partition_named() {
    let (mut engine, base, set_id) = engine_with_system_set("corrupt");
    // Corrupt the stored chunk holding explorer.exe's content:
    // flip a byte in its record on the volume.
    let manifest = read_set_manifest(engine.volume(), &set_id).unwrap();
    let entry = manifest
        .file("osroot/Windows/explorer.exe")
        .expect("explorer is in the set");
    let chunk_id = entry.chunks[0].clone();
    let chunk_path = base
        .join("volume")
        .join("chunks")
        .join(&chunk_id[..2])
        .join(&chunk_id);
    let mut bytes = fs::read(&chunk_path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    fs::write(&chunk_path, bytes).unwrap();

    let staging = base.join("staging");
    let mut events: Vec<Event> = Vec::new();
    let report = engine
        .run_boot_rehearsal(&set_id, &target(), &options(), &staging, None, &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert!(!report.files_verified);
    assert!(!report.passed());
    assert!(
        report.application_error.is_some(),
        "the chunk failure is recorded"
    );
    // The Windows partition is named, with the file missing.
    let windows = report
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Windows)
        .unwrap();
    assert!(
        windows.missing.iter().any(|m| m.contains("explorer.exe")),
        "windows partition report: {windows:?}"
    );
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            summary_id,
            ..
        }) if summary_id == "result.boot_rehearsal_verify_failed"
    ));
    // Even a failed rehearsal says not boot-tested.
    assert!(report.verdict_line().contains(NOT_BOOT_TESTED_LINE));
}

#[test]
fn checklists_split_on_hyperv_and_are_built_from_the_plan() {
    let (mut engine, base, set_id) = engine_with_system_set("lists");
    let staging = base.join("staging");

    let pro = engine
        .plan_boot_rehearsal(
            &set_id,
            &target(),
            &options(),
            &staging,
            Some(&VmFacts {
                hyperv_available: true,
                edition: Some("Windows 11 Pro".to_string()),
            }),
        )
        .unwrap();
    let ids: Vec<&str> = pro.checklist.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&"vm.create_vhdx"));
    assert!(ids.contains(&"vm.boot_vm"));
    assert!(ids.contains(&"record.outcome"));
    let vhdx_step = pro
        .checklist
        .iter()
        .find(|s| s.id == "vm.create_vhdx")
        .unwrap();
    // The command is data built from this plan's target size.
    assert!(vhdx_step
        .command
        .as_deref()
        .unwrap()
        .contains(&(256 * GIB).to_string()));
    // The plan's own boot commands appear as steps.
    assert!(pro.checklist.iter().any(|s| s
        .command
        .as_deref()
        .unwrap_or("")
        .starts_with("bcdboot")));

    let home = engine
        .plan_boot_rehearsal(
            &set_id,
            &target(),
            &options(),
            &staging,
            Some(&VmFacts {
                hyperv_available: false,
                edition: Some("Windows 11 Home".to_string()),
            }),
        )
        .unwrap();
    let ids: Vec<&str> = home.checklist.iter().map(|s| s.id.as_str()).collect();
    assert!(ids.contains(&"home.check_artifacts"));
    assert!(ids.contains(&"home.boot_usb"));
    assert!(!ids.iter().any(|i| i.starts_with("vm.")));
    // The Home path never presents a VM command as available.
    assert!(home
        .checklist
        .iter()
        .all(|s| !s.command.as_deref().unwrap_or("").contains("New-VHD")));
}

#[test]
fn only_the_record_step_with_a_source_can_claim_a_boot() {
    let (mut engine, base, set_id) = engine_with_system_set("record");
    let staging = base.join("staging");
    engine
        .run_boot_rehearsal(&set_id, &target(), &options(), &staging, None, &mut |_| {})
        .unwrap();

    // No source, no record.
    let err = record_vm_boot_outcome(&staging, "reached logon", "", 1_700_100_000).unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidFacts { .. }));
    let still = read_rehearsal_record(&staging).unwrap();
    assert_eq!(still.vm_boot, VmBootStatus::NotBootTested);

    let updated = record_vm_boot_outcome(
        &staging,
        "reached the Windows logon screen in about 3 minutes",
        "operator observation during the on-machine session",
        1_700_100_000,
    )
    .unwrap();
    assert!(matches!(updated.vm_boot, VmBootStatus::Recorded { .. }));
    assert!(updated
        .verdict_line()
        .contains("VM boot recorded: reached the Windows logon screen"));
    assert!(!updated.verdict_line().contains(NOT_BOOT_TESTED_LINE));
}

#[test]
fn layout_validation_catches_a_broken_plan() {
    let (engine, _base, set_id) = engine_with_system_set("layout");
    let manifest = read_set_manifest(engine.volume(), &set_id).unwrap();
    let mut plan = plan_system_restore(&manifest, &target(), &options()).unwrap();
    let (valid, _) = validate_layout(&plan);
    assert!(valid);
    // Break contiguity: shift the Windows partition's offset.
    let win = plan
        .layout
        .iter_mut()
        .find(|p| p.role == PartitionRole::Windows)
        .unwrap();
    win.offset_bytes += 1024;
    let (valid, detail) = validate_layout(&plan);
    assert!(!valid);
    assert!(detail.contains("windows"), "detail: {detail}");
}
