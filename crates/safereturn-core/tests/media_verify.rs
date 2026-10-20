//! S4 slice 3: media manifest + verify + boot-test marker protocol.
//! The honesty core under test: intact-but-untested media reports
//! exactly that; a tampered payload file is named; an invalid marker
//! is reported invalid — never upgraded to "boot-tested".

use safereturn_core::media::*;
use safereturn_core::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

struct BuiltMedia {
    base: PathBuf,
    boot: PathBuf,
    data: PathBuf,
    plan: MediaPlan,
}

fn build_media() -> BuiltMedia {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base =
        std::env::temp_dir().join(format!("safereturn-s4-verify-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    let boot = base.join("boot");
    let data = base.join("data");
    fs::create_dir_all(boot.join("safereturn")).unwrap();
    fs::create_dir_all(&data).unwrap();

    // Payload files as they would sit at the media root.
    let app = b"fake recovery shell binary";
    let cfg = b"{ \"lang\": \"en\" }";
    fs::write(boot.join("safereturn/app.exe"), app).unwrap();
    fs::write(boot.join("safereturn/config.json"), cfg).unwrap();
    // Boot files in the MakeWinPEMedia layout.
    fs::create_dir_all(boot.join("EFI/Boot")).unwrap();
    fs::write(boot.join("EFI/Boot/bootx64.efi"), b"efi loader").unwrap();
    fs::create_dir_all(boot.join("sources")).unwrap();
    fs::write(boot.join("sources/boot.wim"), b"wim").unwrap();

    let payload = vec![
        PayloadFact {
            source_path: "host/app.exe".into(),
            dest_rel: "safereturn/app.exe".into(),
            size_bytes: app.len() as u64,
            sha256: sha256_hex(app),
        },
        PayloadFact {
            source_path: "host/config.json".into(),
            dest_rel: "safereturn/config.json".into(),
            size_bytes: cfg.len() as u64,
            sha256: sha256_hex(cfg),
        },
    ];
    let facts = MediaFacts {
        target: MediaTargetFacts {
            disk_id: "disk-3".into(),
            model: "USB Flash Drive".into(),
            serial_suffix: "X7K2".into(),
            size_bytes: 16 * GIB,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "C:\\WinPE\\boot.wim".into(),
            wim_size_bytes: 400 * MIB,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload,
    };
    let plan = plan_media(&facts, &Default::default()).unwrap();
    write_media_manifest(&boot, &plan, 1_700_003_000).unwrap();
    BuiltMedia {
        base,
        boot,
        data,
        plan,
    }
}

#[test]
fn fresh_media_verifies_intact_and_reports_not_boot_tested() {
    let m = build_media();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(
        report.passed(),
        "payload+boot files should pass: {report:?}"
    );
    assert!(report.payload.iter().all(|p| p.ok));
    assert_eq!(report.manifest.plan_id, m.plan.plan_id);
    // The crucial fact: intact ≠ tested.
    assert_eq!(report.boot_test, BootTestStatus::NotTested);
    assert!(!report.boot_tested());
}

#[test]
fn boot_test_marker_round_trips_and_only_then_counts_as_tested() {
    let m = build_media();
    let marker = record_boot_test(
        &m.data,
        &m.plan.plan_id,
        Some("UEFI".into()),
        true,
        1_700_004_000,
    )
    .unwrap();
    assert_eq!(marker.media_plan_id, m.plan.plan_id);
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert_eq!(
        report.boot_test,
        BootTestStatus::Tested {
            booted_unix: 1_700_004_000,
            firmware: Some("UEFI".into()),
        }
    );
    assert!(report.boot_tested());
}

#[test]
fn marker_that_stopped_before_the_shell_is_not_a_boot_test() {
    let m = build_media();
    record_boot_test(
        &m.data,
        &m.plan.plan_id,
        Some("UEFI".into()),
        false,
        1_700_004_500,
    )
    .unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(matches!(
        report.boot_test,
        BootTestStatus::BootStartedShellNotReached { .. }
    ));
    assert!(!report.boot_tested());
}

#[test]
fn tampered_payload_is_named_not_just_failed() {
    let m = build_media();
    fs::write(m.boot.join("safereturn/app.exe"), b"tampered binary!").unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(!report.passed());
    let bad: Vec<&PayloadCheck> = report.payload.iter().filter(|p| !p.ok).collect();
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].dest_rel, "safereturn/app.exe");
    assert!(
        bad[0].detail.contains("size differs") || bad[0].detail.contains("content differs"),
        "detail should say what is wrong: {}",
        bad[0].detail
    );
    // The untampered file still passes individually.
    assert!(
        report
            .payload
            .iter()
            .find(|p| p.dest_rel == "safereturn/config.json")
            .unwrap()
            .ok
    );
}

#[test]
fn missing_boot_file_fails_the_boot_file_check() {
    let m = build_media();
    fs::remove_file(m.boot.join("sources/boot.wim")).unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(!report.boot_files_ok());
    assert!(!report.passed());
    let wim = report
        .boot_files
        .iter()
        .find(|b| b.path == "sources/boot.wim")
        .unwrap();
    assert!(!wim.present);
}

#[test]
fn garbage_marker_is_invalid_not_tested() {
    let m = build_media();
    fs::write(m.data.join(BOOT_TEST_MARKER_FILE), b"this is not json").unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(matches!(report.boot_test, BootTestStatus::Invalid { .. }));
    assert!(!report.boot_tested());
    // Payload verification is unaffected by the marker's state.
    assert!(report.passed());
}

#[test]
fn marker_for_other_media_is_invalid() {
    let m = build_media();
    record_boot_test(
        &m.data,
        "some-other-plan-id",
        Some("UEFI".into()),
        true,
        1_700_005_000,
    )
    .unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    match &report.boot_test {
        BootTestStatus::Invalid { reason } => {
            assert!(reason.contains("different media"), "reason: {reason}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }
    assert!(!report.boot_tested());
}

#[test]
fn wrong_version_marker_is_invalid() {
    let m = build_media();
    let text = serde_json::json!({
        "format_version": 99,
        "media_plan_id": m.plan.plan_id,
        "booted_unix": 1_700_005_000u64,
        "firmware": "UEFI",
        "reached_shell": true,
    })
    .to_string();
    fs::write(m.data.join(BOOT_TEST_MARKER_FILE), text).unwrap();
    let report = verify_media_roots(&m.boot, Some(&m.data)).unwrap();
    assert!(matches!(report.boot_test, BootTestStatus::Invalid { .. }));
    assert!(!report.boot_tested());
}

#[test]
fn missing_manifest_is_a_named_error_not_a_pass() {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let empty =
        std::env::temp_dir().join(format!("safereturn-s4-empty-{}-{n}", std::process::id()));
    fs::create_dir_all(&empty).unwrap();
    let err = verify_media(&empty).unwrap_err();
    assert!(matches!(err, CoreError::MediaManifestMissing { .. }));
    assert_eq!(err.code(), "media.manifest_missing");
}

#[test]
fn wrong_version_manifest_is_invalid_data() {
    let m = build_media();
    let path = m.boot.join(MEDIA_MANIFEST_FILE);
    let mut v: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    v["format_version"] = serde_json::json!(99);
    fs::write(&path, v.to_string()).unwrap();
    let err = verify_media_roots(&m.boot, Some(&m.data)).unwrap_err();
    assert!(matches!(err, CoreError::MediaManifestInvalid { .. }));
    let _ = Path::new(&m.base);
}
