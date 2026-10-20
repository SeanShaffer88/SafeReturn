//! S5 slice 1: the pure system-restore planner — layout math on
//! several target sizes, every typed refusal, plan determinism, the
//! BitLocker warning present iff the source was protected, and
//! defaults that carry their sources. The planner reads manifest
//! structs directly, so these tests need no volume and run anywhere.

use safereturn_core::sets::{SetFileEntry, SetManifest};
use safereturn_core::system::{
    BcdCapture, BitLockerState, BootMode, EspFile, Fact, SystemFacts, WinReInfo,
};
use safereturn_core::system_restore::{
    plan_system_restore, PartitionRole, SystemRestoreOptions, SystemRestorePostStep,
    SystemRestoreTargetFacts, SystemRestoreWarning, ESP_DEFAULT_BYTES, GPT_END_RESERVE_BYTES,
    GPT_FRONT_RESERVE_BYTES, MSR_BYTES, WINRE_IMAGE_DEST_REL,
};
use safereturn_core::{sha256_hex, CoreError};
use std::collections::BTreeMap;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

fn fake_hash(tag: &str) -> String {
    sha256_hex(tag.as_bytes())
}

fn entry(path: &str, size: u64) -> SetFileEntry {
    SetFileEntry {
        path: path.to_string(),
        size,
        mtime_unix: 0,
        sha256: fake_hash(path),
        chunks: Vec::new(),
    }
}

const WINRE_WIM_SIZE: u64 = 550 * MIB;

/// A plausible system set: an OS root with Windows (incl. the staged
/// Winre.wim) and user data, and an ESP root with the boot files.
fn base_files() -> Vec<SetFileEntry> {
    vec![
        entry("osroot/Windows/explorer.exe", 5_000_000),
        entry("osroot/Windows/System32/kernel32.dll", 1_000_000),
        entry("osroot/Windows/System32/Recovery/Winre.wim", WINRE_WIM_SIZE),
        entry("osroot/Users/Sean/photo.jpg", 2_000_000),
        entry("esproot/EFI/Boot/bootx64.efi", 1_500_000),
        entry("esproot/EFI/Microsoft/Boot/bootmgfw.efi", 1_600_000),
        entry("esproot/EFI/Microsoft/Boot/BCD", 16_384),
    ]
}

fn base_esp_listing() -> Vec<EspFile> {
    base_files()
        .iter()
        .filter(|f| f.path.starts_with("esproot/"))
        .map(|f| EspFile {
            path: f.path.strip_prefix("esproot/").unwrap().to_string(),
            size: f.size,
            sha256: f.sha256.clone(),
        })
        .collect()
}

fn facts(
    boot_mode: Fact<BootMode>,
    secure_boot: Fact<bool>,
    bitlocker_c: Fact<BitLockerState>,
    winre: Fact<WinReInfo>,
) -> SystemFacts {
    let mut bitlocker = BTreeMap::new();
    bitlocker.insert("C:".to_string(), bitlocker_c);
    SystemFacts {
        format_version: 1,
        gathered_unix: 1_700_000_000,
        boot_mode,
        secure_boot,
        bitlocker,
        esp_files: Fact::known(base_esp_listing(), "test esp listing"),
        winre,
        bcd: BcdCapture::not_included("test", "BCD is rebuilt by bcdboot during restore"),
    }
}

fn uefi_facts() -> SystemFacts {
    facts(
        Fact::known(BootMode::Uefi, "test firmware query"),
        Fact::known(true, "test secure boot query"),
        Fact::known(BitLockerState::On, "test bitlocker query"),
        Fact::known(
            WinReInfo {
                present: true,
                location: Some("C:\\Windows\\System32\\Recovery\\Winre.wim".to_string()),
            },
            "test winre query",
        ),
    )
}

fn manifest(files: Vec<SetFileEntry>, system: Option<SystemFacts>) -> SetManifest {
    SetManifest {
        format_version: 1,
        set_id: "2026-10-20-system".to_string(),
        label: "System backup".to_string(),
        created_unix: 1_700_000_000,
        roots: vec!["osroot".to_string(), "esproot".to_string()],
        capture_mode: Default::default(),
        system,
        files,
        skipped: Vec::new(),
    }
}

fn target(size_bytes: u64) -> SystemRestoreTargetFacts {
    SystemRestoreTargetFacts {
        disk_id: "disk-1".to_string(),
        model: "Samsung SSD 990".to_string(),
        serial_suffix: "1234".to_string(),
        size_bytes,
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

// ---------------------------------------------------------------- layout

#[test]
fn layout_math_on_a_256_gib_target() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();

    assert_eq!(plan.layout.len(), 4);
    let esp = plan.partition(PartitionRole::Esp).unwrap();
    let msr = plan.partition(PartitionRole::Msr).unwrap();
    let win = plan.partition(PartitionRole::Windows).unwrap();
    let re = plan.partition(PartitionRole::WinRe).unwrap();

    // ESP content (3_116_384 bytes) + 32 MiB headroom is below the
    // 300 MiB default, so the default sizes the partition.
    assert_eq!(esp.size_bytes, ESP_DEFAULT_BYTES);
    assert_eq!(esp.offset_bytes, GPT_FRONT_RESERVE_BYTES);
    assert_eq!(msr.size_bytes, MSR_BYTES);
    assert_eq!(msr.offset_bytes, esp.offset_bytes + esp.size_bytes);
    // WinRE: 550 MiB image + 200 MiB documented free space.
    assert_eq!(re.size_bytes, WINRE_WIM_SIZE + 200 * MIB);
    assert_eq!(re.type_guid, "de94bba4-06d1-4d40-a16a-bfd50179d6ac");
    assert_eq!(re.gpt_attributes.as_deref(), Some("0x8000000000000001"));
    // Windows takes the remainder; the whole layout + reserves
    // accounts for every byte of the disk.
    let used = GPT_FRONT_RESERVE_BYTES
        + esp.size_bytes
        + msr.size_bytes
        + win.size_bytes
        + re.size_bytes
        + GPT_END_RESERVE_BYTES;
    assert_eq!(used, 256 * GIB);
    assert_eq!(win.offset_bytes, msr.offset_bytes + msr.size_bytes);
    assert_eq!(re.offset_bytes, win.offset_bytes + win.size_bytes);
    // Partition numbers are 1-based in on-disk order.
    assert_eq!(
        plan.layout.iter().map(|p| p.index).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
}

#[test]
fn layout_scales_with_target_size() {
    let m = manifest(base_files(), Some(uefi_facts()));
    for size in [64 * GIB, 500 * GIB, 2 * 1024 * GIB] {
        let plan = plan_system_restore(&m, &target(size), &options()).unwrap();
        let win = plan.partition(PartitionRole::Windows).unwrap();
        let fixed: u64 = plan
            .layout
            .iter()
            .filter(|p| p.role != PartitionRole::Windows)
            .map(|p| p.size_bytes)
            .sum();
        assert_eq!(
            win.size_bytes,
            size - GPT_FRONT_RESERVE_BYTES - fixed - GPT_END_RESERVE_BYTES,
            "windows partition must absorb all remaining space on a {size}-byte target"
        );
        // The Windows partition always holds the data plus headroom.
        assert!(win.size_bytes >= plan.os_bytes + 512 * MIB);
    }
}

#[test]
fn esp_grows_when_recorded_contents_exceed_the_default() {
    let mut files = base_files();
    files.push(entry("esproot/EFI/Dell/diags.efi", 400 * MIB));
    // The ESP fact listing must match the set, or a mismatch warning
    // (not a failure) appears — rebuild facts with the bigger ESP.
    let mut f = uefi_facts();
    f.esp_files = Fact::known(
        files
            .iter()
            .filter(|x| x.path.starts_with("esproot/"))
            .map(|x| EspFile {
                path: x.path.strip_prefix("esproot/").unwrap().to_string(),
                size: x.size,
                sha256: x.sha256.clone(),
            })
            .collect(),
        "test esp listing",
    );
    let m = manifest(files, Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    let esp = plan.partition(PartitionRole::Esp).unwrap();
    // content now 3_116_384 + 400 MiB; + 32 MiB headroom, aligned
    // up to 1 MiB like every partition here.
    let raw = plan.esp_bytes + 32 * MIB;
    assert_eq!(esp.size_bytes, raw.div_ceil(MIB) * MIB);
    assert!(esp.size_source.contains("contents recorded in the backup"));
}

#[test]
fn defaults_carry_their_sources() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    let esp = plan.partition(PartitionRole::Esp).unwrap();
    assert!(
        esp.size_source.contains("Microsoft Learn"),
        "{}",
        esp.size_source
    );
    let msr = plan.partition(PartitionRole::Msr).unwrap();
    assert!(
        msr.size_source.contains("Microsoft Learn"),
        "{}",
        msr.size_source
    );
    let re = plan.partition(PartitionRole::WinRe).unwrap();
    assert!(re.size_source.contains("3135522"), "{}", re.size_source);
}

#[test]
fn applications_map_every_file_to_its_partition() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    // 7 set files + the WinRE placement copy.
    assert_eq!(plan.applications.len(), 8);
    let esp_apps: Vec<_> = plan
        .applications
        .iter()
        .filter(|a| a.partition == PartitionRole::Esp)
        .collect();
    assert_eq!(esp_apps.len(), 3);
    assert!(esp_apps
        .iter()
        .all(|a| a.set_path.starts_with("esproot/") && !a.dest_rel.contains("esproot")));
    let winre_app = plan
        .applications
        .iter()
        .find(|a| a.partition == PartitionRole::WinRe)
        .unwrap();
    assert_eq!(winre_app.dest_rel, WINRE_IMAGE_DEST_REL);
    assert_eq!(
        winre_app.set_path,
        "osroot/Windows/System32/Recovery/Winre.wim"
    );
    // The staged Winre.wim is ALSO applied to the Windows partition
    // at its natural path (it is part of the OS files).
    assert!(plan
        .applications
        .iter()
        .any(|a| a.partition == PartitionRole::Windows
            && a.dest_rel == "Windows/System32/Recovery/Winre.wim"));
    assert_eq!(plan.total_file_count(), 8);
}

#[test]
fn post_steps_render_the_documented_commands() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    let commands: Vec<Vec<String>> = plan.post_steps.iter().filter_map(|s| s.command()).collect();
    assert_eq!(
        commands[0],
        vec!["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"]
    );
    assert_eq!(
        commands[1],
        vec![
            "reagentc",
            "/setreimage",
            "/path",
            "R:\\Recovery\\WindowsRE",
            "/target",
            "W:\\Windows"
        ]
    );
    assert_eq!(commands[2], vec!["reagentc", "/enable"]);
}

#[test]
fn plan_is_deterministic_and_round_trips() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let a = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    let b = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.plan_id.len(), 64);
    let json = serde_json::to_string(&a).unwrap();
    let back: safereturn_core::system_restore::SystemRestorePlan =
        serde_json::from_str(&json).unwrap();
    assert_eq!(a, back);
    // A different target size is a different plan.
    let c = plan_system_restore(&m, &target(512 * GIB), &options()).unwrap();
    assert_ne!(a.plan_id, c.plan_id);
}

// -------------------------------------------------------------- refusals

#[test]
fn file_only_set_is_refused_by_name() {
    let m = manifest(base_files(), None);
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreNotASystemSet { .. }));
    assert_eq!(err.code(), "system_restore.not_a_system_set");
}

#[test]
fn bios_source_is_refused_not_converted() {
    let mut f = uefi_facts();
    f.boot_mode = Fact::known(BootMode::Bios, "test firmware query");
    let m = manifest(base_files(), Some(f));
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreFirmwareUnsupported { .. }
    ));
    assert_eq!(err.code(), "system_restore.firmware_unsupported");
}

#[test]
fn unknown_source_firmware_is_refused() {
    let mut f = uefi_facts();
    f.boot_mode = Fact::unknown("test firmware query", "firmware query not implemented");
    let m = manifest(base_files(), Some(f));
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreFirmwareUnknown { .. }
    ));
    assert_eq!(err.code(), "system_restore.firmware_unknown");
}

#[test]
fn firmware_mismatch_is_refused() {
    let mut t = target(256 * GIB);
    t.firmware = Fact::known(BootMode::Bios, "test firmware query");
    let m = manifest(base_files(), Some(uefi_facts()));
    let err = plan_system_restore(&m, &t, &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreFirmwareMismatch { .. }
    ));
    assert_eq!(err.code(), "system_restore.firmware_mismatch");

    let mut t2 = target(256 * GIB);
    t2.firmware = Fact::unknown("test firmware query", "could not query firmware");
    let err = plan_system_restore(&m, &t2, &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreFirmwareUnknown { .. }
    ));
}

#[test]
fn too_small_target_is_refused_with_computed_minimum() {
    let mut files = base_files();
    files.push(entry("osroot/Windows/WinSxS/blob.bin", 20 * GIB));
    let m = manifest(files, Some(uefi_facts()));
    let err = plan_system_restore(&m, &target(16 * GIB), &options()).unwrap_err();
    match err {
        CoreError::SystemRestoreTargetTooSmall {
            needed_bytes,
            size_bytes,
        } => {
            assert_eq!(size_bytes, 16 * GIB);
            assert!(needed_bytes > 20 * GIB, "needed {needed_bytes}");
        }
        other => panic!("wrong error: {other:?}"),
    }
}

#[test]
fn unmapped_extra_root_is_refused_not_dropped() {
    let mut files = base_files();
    files.push(entry("dataroot/Documents/tax.pdf", 12_000));
    let mut m = manifest(files, Some(uefi_facts()));
    m.roots.push("dataroot".to_string());
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidFacts { .. }));
    assert!(err.to_string().contains("dataroot"), "{err}");
}

#[test]
fn missing_named_root_is_refused() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let bad = SystemRestoreOptions {
        os_root: "nope".to_string(),
        esp_root: "esproot".to_string(),
    };
    let err = plan_system_restore(&m, &target(256 * GIB), &bad).unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidFacts { .. }));
}

#[test]
fn missing_boot_files_are_refused() {
    // ESP captured, but the Windows Boot Manager is absent.
    let files: Vec<_> = base_files()
        .into_iter()
        .filter(|f| f.path != "esproot/EFI/Microsoft/Boot/bootmgfw.efi")
        .collect();
    let mut f = uefi_facts();
    f.esp_files = Fact::known(
        files
            .iter()
            .filter(|x| x.path.starts_with("esproot/"))
            .map(|x| EspFile {
                path: x.path.strip_prefix("esproot/").unwrap().to_string(),
                size: x.size,
                sha256: x.sha256.clone(),
            })
            .collect(),
        "test esp listing",
    );
    let m = manifest(files, Some(f));
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreBootFilesMissing { .. }
    ));
    assert!(err.to_string().contains("bootmgfw.efi"), "{err}");

    // No ESP content at all.
    let files: Vec<_> = base_files()
        .into_iter()
        .filter(|f| !f.path.starts_with("esproot/"))
        .collect();
    let m = manifest(files, Some(uefi_facts()));
    let err = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap_err();
    assert!(matches!(
        err,
        CoreError::SystemRestoreBootFilesMissing { .. }
    ));
}

#[test]
fn bad_serial_suffix_is_refused() {
    let mut t = target(256 * GIB);
    t.serial_suffix = "12345".to_string();
    let m = manifest(base_files(), Some(uefi_facts()));
    let err = plan_system_restore(&m, &t, &options()).unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidFacts { .. }));
}

// ------------------------------------------------------- disclosed gaps

#[test]
fn missing_winre_image_is_a_warning_not_a_refusal() {
    let files: Vec<_> = base_files()
        .into_iter()
        .filter(|f| f.path != "osroot/Windows/System32/Recovery/Winre.wim")
        .collect();
    let m = manifest(files, Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan.partition(PartitionRole::WinRe).is_none());
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, SystemRestoreWarning::WinReMissing { .. })));
    // No reagentc steps without an image to register.
    assert!(!plan
        .post_steps
        .iter()
        .any(|s| matches!(s, SystemRestorePostStep::ReagentcEnable)));
}

#[test]
fn no_winre_on_source_is_disclosed_too() {
    let mut f = uefi_facts();
    f.winre = Fact::known(
        WinReInfo {
            present: false,
            location: None,
        },
        "test winre query",
    );
    // Keep the image out of the set as well, so nothing contradicts.
    let files: Vec<_> = base_files()
        .into_iter()
        .filter(|f| f.path != "osroot/Windows/System32/Recovery/Winre.wim")
        .collect();
    let m = manifest(files, Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.winre_missing"));
    assert!(plan.partition(PartitionRole::WinRe).is_none());
}

#[test]
fn bitlocker_warning_present_iff_source_protected() {
    // On → warning + a notice post-step carrying the plain-language text.
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| matches!(w, SystemRestoreWarning::BitLockerNotRestored { .. })));
    assert!(plan.post_steps.iter().any(|s| matches!(
        s,
        SystemRestorePostStep::Notice { id, text }
        if id == "system_restore.bitlocker_notice" && text.contains("NOT encrypted")
    )));

    // Suspended counts as protected (it was on; protection paused).
    let mut f = uefi_facts();
    f.bitlocker.insert(
        "C:".to_string(),
        Fact::known(BitLockerState::Suspended, "test bitlocker query"),
    );
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.bitlocker_not_restored"));

    // Off → neither warning nor notice.
    let mut f = uefi_facts();
    f.bitlocker.insert(
        "C:".to_string(),
        Fact::known(BitLockerState::Off, "test bitlocker query"),
    );
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(!plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.bitlocker_not_restored"));
    assert!(!plan.post_steps.iter().any(|s| matches!(
        s,
        SystemRestorePostStep::Notice { id, .. } if id == "system_restore.bitlocker_notice"
    )));

    // Unknown → the unknown warning, never the protected claim.
    let mut f = uefi_facts();
    f.bitlocker.insert(
        "C:".to_string(),
        Fact::unknown("test bitlocker query", "WMI query failed"),
    );
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.bitlocker_state_unknown"));
    assert!(!plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.bitlocker_not_restored"));
}

#[test]
fn secure_boot_note_only_when_source_had_it_on() {
    let m = manifest(base_files(), Some(uefi_facts()));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan.post_steps.iter().any(|s| matches!(
        s,
        SystemRestorePostStep::Notice { id, .. } if id == "system_restore.secure_boot_note"
    )));

    let mut f = uefi_facts();
    f.secure_boot = Fact::known(false, "test secure boot query");
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(!plan.post_steps.iter().any(|s| matches!(
        s,
        SystemRestorePostStep::Notice { id, .. } if id == "system_restore.secure_boot_note"
    )));

    let mut f = uefi_facts();
    f.secure_boot = Fact::unknown("test secure boot query", "variable not readable");
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.secure_boot_state_unknown"));
}

#[test]
fn esp_listing_drift_is_disclosed() {
    // The recorded listing names a file the set does not carry (not
    // a boot file): plan proceeds, drift is a warning.
    let mut f = uefi_facts();
    let mut listing = base_esp_listing();
    listing.push(EspFile {
        path: "EFI/OEM/logo.bmp".to_string(),
        size: 40_000,
        sha256: fake_hash("logo"),
    });
    f.esp_files = Fact::known(listing, "test esp listing");
    let m = manifest(base_files(), Some(f));
    let plan = plan_system_restore(&m, &target(256 * GIB), &options()).unwrap();
    assert!(plan
        .warnings
        .iter()
        .any(|w| w.id() == "system_restore.esp_facts_mismatch"));
}
