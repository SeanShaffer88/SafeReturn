//! S3 acceptance tests for system facts (see docs/S3_NOTES.md).
//! The promises pinned here: facts attach to a set and read back
//! exactly; invalid facts (unknown without reason, sourceless fact,
//! ambiguous BCD) are refused; recorded facts are never silently
//! replaced; ESP listing is real (paths, sizes, hashes).

use safereturn_core::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!(
        "safereturn-s3sys-{name}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn open_test_volume(base: &Path) -> UnlockedVolume {
    let vroot = base.join("volume");
    let (locked, _) = Volume::create(&vroot, "correct horse battery", 1_700_000_000).unwrap();
    locked
        .unlock_with_passphrase("correct horse battery")
        .unwrap()
}

fn sample_facts() -> SystemFacts {
    let mut bitlocker = BTreeMap::new();
    bitlocker.insert(
        "C:".to_string(),
        Fact::known(BitLockerState::On, "fake gatherer (tests)"),
    );
    bitlocker.insert(
        "D:".to_string(),
        Fact::unknown(
            "fake gatherer (tests)",
            "the test gatherer does not inspect D:",
        ),
    );
    SystemFacts {
        format_version: SYSTEM_FACTS_FORMAT_VERSION,
        gathered_unix: 1_700_005_000,
        boot_mode: Fact::known(BootMode::Uefi, "fake gatherer (tests)"),
        secure_boot: Fact::known(true, "fake gatherer (tests)"),
        bitlocker,
        esp_files: Fact::known(
            vec![EspFile {
                path: "EFI/Microsoft/Boot/bootmgfw.efi".to_string(),
                size: 5,
                sha256: sha256_hex(b"boot!"),
            }],
            "fake gatherer (tests)",
        ),
        winre: Fact::known(
            WinReInfo {
                present: true,
                location: Some("C:\\Windows\\System32\\Recovery\\Winre.wim".to_string()),
            },
            "fake gatherer (tests)",
        ),
        bcd: BcdCapture::not_included(
            "fake gatherer (tests)",
            "the test gatherer never captures the BCD store",
        ),
    }
}

fn make_set(volume: &UnlockedVolume, base: &Path) -> SetManifest {
    let src = base.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    let mut noop = |_: u64, _: u64| {};
    backup_tree(volume, "sys", &[src], 1_700_005_100, &mut noop)
        .unwrap()
        .manifest
}

#[test]
fn facts_attach_and_read_back_exactly() {
    let base = tmp("attach");
    let volume = open_test_volume(&base);
    let manifest = make_set(&volume, &base);
    assert!(
        manifest.system.is_none(),
        "plain file set has no system section"
    );

    let facts = sample_facts();
    let updated = attach_system_facts(&volume, &manifest.set_id, facts.clone()).unwrap();
    assert_eq!(updated.system.as_ref().unwrap(), &facts);

    // Read back from disk: identical, and a file set's other fields are
    // untouched.
    let read = read_set_manifest(&volume, &manifest.set_id).unwrap();
    assert_eq!(read.system.as_ref().unwrap(), &facts);
    assert_eq!(read.files.len(), 1);
    assert_eq!(read.capture_mode, CaptureMode::Live);

    // The facts survive in the JSON with sources and reasons visible.
    let text = fs::read_to_string(
        volume
            .root()
            .join("sets")
            .join(format!("{}.json", manifest.set_id)),
    )
    .unwrap();
    assert!(text.contains("\"boot_mode\""));
    assert!(text.contains("fake gatherer (tests)"));
    assert!(text.contains("the test gatherer does not inspect D:"));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn recorded_facts_are_never_silently_replaced() {
    let base = tmp("no-replace");
    let volume = open_test_volume(&base);
    let manifest = make_set(&volume, &base);
    attach_system_facts(&volume, &manifest.set_id, sample_facts()).unwrap();
    let err = attach_system_facts(&volume, &manifest.set_id, sample_facts()).unwrap_err();
    assert!(matches!(err, CoreError::SystemFactsAlreadyPresent { .. }));
    assert_eq!(err.code(), "set.system_facts_already_present");
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn invalid_facts_are_refused_with_reasons() {
    let base = tmp("invalid");
    let volume = open_test_volume(&base);
    let manifest = make_set(&volume, &base);

    // Unknown without a reason.
    let mut facts = sample_facts();
    facts.secure_boot = Fact {
        value: None,
        source: "fake gatherer (tests)".to_string(),
        unknown_reason: None,
    };
    let err = attach_system_facts(&volume, &manifest.set_id, facts).unwrap_err();
    assert!(
        matches!(err, CoreError::InvalidSystemFacts { .. }),
        "got: {err:?}"
    );
    assert!(
        format!("{err}").contains("secure_boot"),
        "error names the fact: {err}"
    );

    // Known value that also carries an unknown-reason.
    let mut facts = sample_facts();
    facts.boot_mode = Fact {
        value: Some(BootMode::Bios),
        source: "fake gatherer (tests)".to_string(),
        unknown_reason: Some("contradiction".to_string()),
    };
    assert!(matches!(
        attach_system_facts(&volume, &manifest.set_id, facts),
        Err(CoreError::InvalidSystemFacts { .. })
    ));

    // Sourceless fact.
    let mut facts = sample_facts();
    facts.winre = Fact::known(
        WinReInfo {
            present: false,
            location: None,
        },
        "",
    );
    assert!(matches!(
        attach_system_facts(&volume, &manifest.set_id, facts),
        Err(CoreError::InvalidSystemFacts { .. })
    ));

    // BCD marked included but with no set path.
    let mut facts = sample_facts();
    facts.bcd = BcdCapture {
        included: true,
        set_path: None,
        source: "fake gatherer (tests)".to_string(),
        not_included_reason: None,
    };
    assert!(matches!(
        attach_system_facts(&volume, &manifest.set_id, facts),
        Err(CoreError::InvalidSystemFacts { .. })
    ));

    // Unsupported facts format version.
    let mut facts = sample_facts();
    facts.format_version = 99;
    assert!(matches!(
        attach_system_facts(&volume, &manifest.set_id, facts),
        Err(CoreError::InvalidSystemFacts { .. })
    ));

    // After all refusals the set still has no system section.
    assert!(read_set_manifest(&volume, &manifest.set_id)
        .unwrap()
        .system
        .is_none());
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn unavailable_gatherer_records_unknowns_with_reasons() {
    let gatherer = UnavailableGatherer {
        reason: "test platform has no gatherer".to_string(),
    };
    let facts = gatherer.gather(None, 1_700_006_000).unwrap();
    facts.validate().unwrap();
    assert!(!facts.boot_mode.is_known());
    assert_eq!(
        facts.boot_mode.unknown_reason.as_deref(),
        Some("test platform has no gatherer")
    );
    assert!(!facts.bcd.included);
    assert!(facts.bcd.not_included_reason.is_some());
    assert_eq!(facts.gathered_unix, 1_700_006_000);
}

#[test]
fn static_gatherer_round_trips_and_validates() {
    let gatherer = StaticFactsGatherer::new(sample_facts());
    let facts = gatherer.gather(None, 0).unwrap();
    assert_eq!(facts, sample_facts());

    // The facts-file format parses back to identical facts.
    let json = serde_json::to_string_pretty(&facts).unwrap();
    assert_eq!(parse_system_facts(&json).unwrap(), facts);

    // A damaged facts file is a named error, not a panic.
    assert!(parse_system_facts("{nope").is_err());
}

#[test]
fn esp_listing_hashes_real_files() {
    let base = tmp("esp");
    let esp = base.join("esp-root");
    fs::create_dir_all(esp.join("EFI/Microsoft/Boot")).unwrap();
    fs::create_dir_all(esp.join("EFI/Boot")).unwrap();
    fs::write(esp.join("EFI/Microsoft/Boot/bootmgfw.efi"), b"boot!").unwrap();
    fs::write(esp.join("EFI/Boot/bootx64.efi"), b"fallback").unwrap();

    let files = list_esp_files(&esp).unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].path, "EFI/Boot/bootx64.efi");
    assert_eq!(files[0].size, 8);
    assert_eq!(files[0].sha256, sha256_hex(b"fallback"));
    assert_eq!(files[1].path, "EFI/Microsoft/Boot/bootmgfw.efi");
    assert_eq!(files[1].sha256, sha256_hex(b"boot!"));

    // esp_fact wraps the same listing with provenance.
    let fact = esp_fact(&esp, "test ESP root");
    assert!(fact.is_known());
    assert_eq!(fact.source, "test ESP root");

    // A missing root becomes an explicit unknown, not an error.
    let missing = esp_fact(&base.join("no-such-dir"), "test ESP root");
    assert!(!missing.is_known());
    assert!(missing.unknown_reason.is_some());

    let _ = fs::remove_dir_all(&base);
}
