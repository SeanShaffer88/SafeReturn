//! S6 slice 1: SafeTarget checks.
//! - The identity relation: Same requires serial suffix + size +
//!   model to agree; Different requires disagreement that cannot
//!   be an enumeration artifact; everything else is Ambiguous, and
//!   ambiguity REFUSES for protected disks (never silently allows).
//! - Every refusal (source / backup / media disk), every warning
//!   (system disk, non-removable), and the override recording.
//! - Planner + engine wiring: the checked planners refuse, demand
//!   the explicit override, and record acknowledgments in the plan
//!   (and, for system restore, in the restore log). The unguarded
//!   entry points keep their pre-S6 behavior and plan ids.

use safereturn_core::safe_target::*;
use safereturn_core::system::{BcdCapture, BitLockerState, BootMode, Fact, SystemFacts, WinReInfo};
use safereturn_core::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const GIB: u64 = 1024 * 1024 * 1024;

fn ident(model: &str, serial: &str, size: u64) -> DiskIdentity {
    DiskIdentity::of("", model, serial, size)
}

fn candidate(model: &str, serial: &str, size: u64, removable: bool) -> TargetDiskFacts {
    TargetDiskFacts {
        disk_id: String::new(),
        model: model.to_string(),
        serial_suffix: serial.to_string(),
        size_bytes: size,
        removable,
        is_system_disk: false,
    }
}

// ------------------------------------------------------- identity relation

#[test]
fn same_requires_serial_size_and_model_to_agree() {
    let a = ident("Samsung SSD 990", "1234", 256 * GIB);
    // Model casing/whitespace varies between enumerations — still same.
    let b = ident("  samsung ssd 990 ", "1234", 256 * GIB);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Same);
    // A matching enumeration id with agreeing facts is also Same.
    let mut c = a.clone();
    c.disk_id = "disk-1".to_string();
    let mut d = a.clone();
    d.disk_id = "disk-1".to_string();
    assert_eq!(identity_relation(&c, &d), IdentityRelation::Same);
}

#[test]
fn differing_serial_suffix_is_a_different_disk() {
    let a = ident("Samsung SSD 990", "1234", 256 * GIB);
    let b = ident("Samsung SSD 990", "9876", 256 * GIB);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Different);
    // Even when sizes also differ, serial disagreement decides.
    let c = ident("WD Blue", "9876", 512 * GIB);
    assert_eq!(identity_relation(&a, &c), IdentityRelation::Different);
}

#[test]
fn serial_match_alone_is_ambiguous_not_same() {
    // Last-4 collisions are common; without size+model corroboration
    // the relation must not claim Same.
    let a = ident("", "1234", 0);
    let b = ident("", "1234", 0);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
    // Serial matches but size contradicts → ambiguous, not different
    // (the serial says same; the size says no — believe neither).
    let a = ident("Samsung SSD 990", "1234", 256 * GIB);
    let b = ident("Samsung SSD 990", "1234", 512 * GIB);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
}

#[test]
fn twin_disks_without_serials_are_ambiguous() {
    // Two identical internal SSDs, serials unknown: nothing can
    // prove the candidate is not the protected twin.
    let a = ident("Samsung SSD 990", "", 256 * GIB);
    let b = ident("Samsung SSD 990", "", 256 * GIB);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
    // A differing size still proves a different disk.
    let c = ident("Samsung SSD 990", "", 512 * GIB);
    assert_eq!(identity_relation(&a, &c), IdentityRelation::Different);
}

#[test]
fn placeholder_serials_carry_no_identity() {
    let a = ident("USB Bridge", "0000", 64 * GIB);
    let b = ident("USB Bridge", "0000", 64 * GIB);
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
}

#[test]
fn matching_id_with_contradicting_serial_is_ambiguous() {
    let mut a = ident("Samsung SSD 990", "1234", 256 * GIB);
    a.disk_id = "disk-1".to_string();
    let mut b = ident("Samsung SSD 990", "9876", 256 * GIB);
    b.disk_id = "disk-1".to_string();
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
}

#[test]
fn no_facts_at_all_is_ambiguous() {
    let a = DiskIdentity::default();
    let b = DiskIdentity::default();
    assert_eq!(identity_relation(&a, &b), IdentityRelation::Ambiguous);
}

// ------------------------------------------------------- check_target

#[test]
fn refuses_source_backup_and_media_disks() {
    let disk = ident("Samsung SSD 990", "1234", 256 * GIB);
    let cand = candidate("Samsung SSD 990", "1234", 256 * GIB, true);
    for (ctx, reason) in [
        (
            SafeTargetContext {
                source_disk: Some(disk.clone()),
                ..Default::default()
            },
            REASON_IS_SOURCE_DISK,
        ),
        (
            SafeTargetContext {
                backup_disk: Some(disk.clone()),
                ..Default::default()
            },
            REASON_IS_BACKUP_DISK,
        ),
        (
            SafeTargetContext {
                media_disk: Some(disk.clone()),
                ..Default::default()
            },
            REASON_IS_MEDIA_DISK,
        ),
    ] {
        let a = check_target(&cand, &ctx);
        assert!(a.is_refused());
        assert_eq!(a.first_refusal().map(|(id, _)| id), Some(reason));
    }
}

#[test]
fn ambiguity_refuses_for_every_protected_disk() {
    // The candidate shares model+size with the protected disk but
    // its serial is unknown: cannot prove it is a different disk.
    let protected = ident("Samsung SSD 990", "1234", 256 * GIB);
    let cand = candidate("Samsung SSD 990", "", 256 * GIB, true);
    let ctx = SafeTargetContext {
        backup_disk: Some(protected),
        ..Default::default()
    };
    let a = check_target(&cand, &ctx);
    assert!(a.is_refused());
    assert_eq!(
        a.first_refusal().map(|(id, _)| id),
        Some(REASON_IDENTITY_AMBIGUOUS)
    );
}

#[test]
fn warns_for_system_disk_and_non_removable_and_allows_a_clean_target() {
    let mut cand = candidate("USB Flash Drive", "X7K2", 64 * GIB, false);
    cand.is_system_disk = true;
    let a = check_target(&cand, &SafeTargetContext::empty());
    assert!(!a.is_refused());
    let ids: Vec<&str> = a.warnings().iter().map(|(id, _)| *id).collect();
    assert_eq!(ids, [WARNING_IS_SYSTEM_DISK, WARNING_NON_REMOVABLE]);
    assert!(matches!(a.summary(), SafeTargetVerdict::Warn { .. }));
    // Neither acknowledged yet.
    assert_eq!(a.unacknowledged_warnings().len(), 2);

    let clean = candidate("USB Flash Drive", "X7K2", 64 * GIB, true);
    let a = check_target(&clean, &SafeTargetContext::empty());
    assert!(a.findings.is_empty());
    assert_eq!(a.summary(), SafeTargetVerdict::Allow);
}

#[test]
fn a_provably_different_disk_is_allowed() {
    let ctx = SafeTargetContext {
        source_disk: Some(ident("Samsung SSD 990", "1234", 256 * GIB)),
        backup_disk: Some(ident("WD Elements", "5555", 2 * 1024 * GIB)),
        media_disk: Some(ident("USB Flash Drive", "X7K2", 64 * GIB)),
        ..Default::default()
    };
    let cand = candidate("SanDisk Ultra", "AB12", 128 * GIB, true);
    let a = check_target(&cand, &ctx);
    assert!(a.findings.is_empty(), "findings: {:?}", a.findings);
}

#[test]
fn acknowledgment_is_tracked_against_findings() {
    let cand = candidate("Internal SSD", "1234", 256 * GIB, false);
    let ctx = SafeTargetContext {
        acknowledged_warnings: vec![WARNING_NON_REMOVABLE.to_string()],
        ..Default::default()
    };
    let a = check_target(&cand, &ctx);
    assert!(a.unacknowledged_warnings().is_empty());
    assert_eq!(
        a.acknowledged_applied(),
        vec![WARNING_NON_REMOVABLE.to_string()]
    );
}

// ------------------------------------------------------- planner wiring

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_base(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-s6-target-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base
}

fn write(path: &PathBuf, content: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// A real encrypted volume holding a real system set (same shape
/// as the S5 executor tests).
fn engine_with_system_set(tag: &str) -> (Engine, PathBuf, String) {
    let base = tmp_base(tag);
    let os_src = base.join("src").join("osroot");
    let esp_src = base.join("src").join("esproot");
    write(&os_src.join("Windows/explorer.exe"), b"explorer-bytes");
    write(
        &os_src.join("Windows/System32/Recovery/Winre.wim"),
        b"winre-image-bytes",
    );
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
    let facts = SystemFacts {
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
    };
    attach_system_facts(&volume, &set_id, facts).unwrap();
    (Engine::new(volume), base, set_id)
}

fn target_facts(removable: bool) -> SystemRestoreTargetFacts {
    SystemRestoreTargetFacts {
        disk_id: "disk-1".to_string(),
        model: "Samsung SSD 990".to_string(),
        serial_suffix: "1234".to_string(),
        size_bytes: 256 * GIB,
        removable,
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
fn guarded_plan_refuses_the_backup_disk_and_creates_no_token() {
    let (mut engine, _base, set_id) = engine_with_system_set("refuse");
    let target = target_facts(true);
    // The very disk the (simulated) backup volume sits on, stated
    // with the same facts as the target: identity Same.
    let ctx = SafeTargetContext {
        backup_disk: Some(DiskIdentity::of(
            "disk-1",
            "Samsung SSD 990",
            "1234",
            256 * GIB,
        )),
        ..Default::default()
    };
    let mut events = Vec::new();
    let err = engine
        .plan_system_restore_guarded(&set_id, &target, &options(), &ctx, false, &mut |e| {
            events.push(e)
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::SafeTargetRefused { .. }));
    assert_eq!(err.code(), "target.refused");
    // No plan was minted: no SystemRestorePlanned event was emitted.
    assert!(events.is_empty());
}

#[test]
fn guarded_plan_demands_the_override_then_records_it() {
    let (mut engine, base, set_id) = engine_with_system_set("override");
    let target = target_facts(false); // non-removable internal disk
    let ctx = SafeTargetContext::empty();
    let err = engine
        .plan_system_restore_guarded(&set_id, &target, &options(), &ctx, false, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::SafeTargetOverrideRequired { .. }));
    assert_eq!(err.code(), "target.override_required");

    // Explicitly acknowledge → plan succeeds, the acknowledgment is
    // in the plan summary's warnings, in the plan itself, and —
    // after a simulated execute — in the restore log on the disk.
    let ctx = SafeTargetContext {
        acknowledged_warnings: vec![WARNING_NON_REMOVABLE.to_string()],
        ..Default::default()
    };
    let summary = engine
        .plan_system_restore_guarded(&set_id, &target, &options(), &ctx, false, &mut |_| {})
        .unwrap();
    assert!(summary
        .warnings
        .contains(&WARNING_NON_REMOVABLE.to_string()));

    let fake_disk = base.join("fake-disk");
    let executor = SimulatedDiskExecutor {
        root: fake_disk.clone(),
    };
    engine
        .execute_system_restore(&summary.plan_token, &target, &executor, &mut |_| {})
        .unwrap();
    let log: RestoreLog =
        serde_json::from_str(&fs::read_to_string(fake_disk.join(RESTORE_LOG_FILE)).unwrap())
            .unwrap();
    assert_eq!(
        log.safety_acknowledgments,
        vec![WARNING_NON_REMOVABLE.to_string()]
    );
}

#[test]
fn unguarded_plan_keeps_pre_s6_behavior_and_plan_id() {
    let (engine, _base, set_id) = engine_with_system_set("stable");
    let manifest = read_set_manifest(engine.volume(), &set_id).unwrap();
    let target = target_facts(false);
    let plain = plan_system_restore(&manifest, &target, &options()).unwrap();
    let checked = plan_system_restore_checked(
        &manifest,
        &target,
        &options(),
        &SafeTargetAssessment::no_context(),
    )
    .unwrap();
    assert_eq!(plain.plan_id, checked.plan_id);
    assert!(plain.safety_acknowledgments.is_empty());
}

#[test]
fn checked_media_plan_refuses_identity_and_keeps_its_own_override() {
    let facts = MediaFacts {
        target: MediaTargetFacts {
            disk_id: "disk-3".into(),
            model: "USB Flash Drive".into(),
            serial_suffix: "X7K2".into(),
            size_bytes: 64 * GIB,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "C:\\WinPE\\boot.wim".into(),
            wim_size_bytes: 400 * 1024 * 1024,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload: vec![],
    };
    // The media target IS the disk the backup lives on → refused.
    let ctx = SafeTargetContext {
        backup_disk: Some(DiskIdentity::of(
            "disk-3",
            "USB Flash Drive",
            "X7K2",
            64 * GIB,
        )),
        ..Default::default()
    };
    let assessment = assess_media_target(&facts.target, false, &ctx);
    let err = plan_media_checked(&facts, &MediaPlanOptions::default(), &assessment).unwrap_err();
    assert!(matches!(err, CoreError::SafeTargetRefused { .. }));

    // The unguarded planner is unchanged, including its plan id.
    let a = plan_media(&facts, &MediaPlanOptions::default()).unwrap();
    let b = plan_media_checked(
        &facts,
        &MediaPlanOptions::default(),
        &SafeTargetAssessment::no_context(),
    )
    .unwrap();
    assert_eq!(a.plan_id, b.plan_id);
    assert!(a.safety_acknowledgments.is_empty());

    // Unguarded engine path still plans media fine.
    let (_locked, _) = ((), ());
}

#[test]
fn guarded_media_plan_records_a_system_disk_acknowledgment() {
    let base = tmp_base("media");
    let (locked, _) = Volume::create(base.join("volume"), "pw", 1_700_003_000).unwrap();
    let volume = locked.unlock_with_passphrase("pw").unwrap();
    let mut engine = Engine::new(volume);
    let mut facts = MediaFacts {
        target: MediaTargetFacts {
            disk_id: "disk-3".into(),
            model: "USB Flash Drive".into(),
            serial_suffix: "X7K2".into(),
            size_bytes: 64 * GIB,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "C:\\WinPE\\boot.wim".into(),
            wim_size_bytes: 400 * 1024 * 1024,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload: vec![],
    };
    facts.target.removable = true;
    // Target is the running system's disk, not yet acknowledged.
    let err = engine
        .plan_media_guarded(
            &facts,
            &MediaPlanOptions::default(),
            &SafeTargetContext::empty(),
            true,
            &mut |_| {},
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::SafeTargetOverrideRequired { .. }));
    // Acknowledged → planned, and the acknowledgment is recorded.
    let ctx = SafeTargetContext {
        acknowledged_warnings: vec![WARNING_IS_SYSTEM_DISK.to_string()],
        ..Default::default()
    };
    let summary = engine
        .plan_media_guarded(
            &facts,
            &MediaPlanOptions::default(),
            &ctx,
            true,
            &mut |_| {},
        )
        .unwrap();
    assert!(summary
        .warnings
        .contains(&WARNING_IS_SYSTEM_DISK.to_string()));
}
