//! S5 slice 3: restore verification. The semantics under test:
//! - a faithfully simulated restore verifies: every planned file
//!   present with matching hash, required ESP boot files present,
//!   WinRE image present iff the plan placed one;
//! - tampering is NAMED (which partition, which path, missing vs
//!   mismatched) — never a bare "failed";
//! - `boot_files_registered` stays NOT VERIFIED even for a perfect
//!   simulated restore: files in place ≠ boot registered, and only
//!   the on-machine flow may ever set that fact.

use safereturn_core::system::{BcdCapture, BitLockerState, BootMode, Fact, SystemFacts, WinReInfo};
use safereturn_core::system_restore_exec::SimulatedDiskExecutor;
use safereturn_core::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const GIB: u64 = 1024 * 1024 * 1024;

fn write(path: &PathBuf, content: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

/// Run a full simulated restore and return (plan, fake disk root).
fn simulated_restore(tag: &str, include_winre: bool) -> (SystemRestorePlan, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-s5-verify-{tag}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let os_src = base.join("src").join("osroot");
    let esp_src = base.join("src").join("esproot");
    write(&os_src.join("Windows/explorer.exe"), b"explorer-bytes");
    if include_winre {
        write(
            &os_src.join("Windows/System32/Recovery/Winre.wim"),
            b"winre-image-bytes",
        );
    }
    write(&esp_src.join("EFI/Boot/bootx64.efi"), b"bootx64");
    write(
        &esp_src.join("EFI/Microsoft/Boot/bootmgfw.efi"),
        b"bootmgfw",
    );

    let (locked, _) = Volume::create(base.join("volume"), "pw", 1_700_004_000).unwrap();
    let volume = locked.unlock_with_passphrase("pw").unwrap();
    let outcome = backup_tree(
        &volume,
        "System backup",
        &[os_src.clone(), esp_src.clone()],
        1_700_004_000,
        &mut |_, _| {},
    )
    .unwrap();
    let set_id = outcome.manifest.set_id.clone();
    let mut bitlocker = BTreeMap::new();
    bitlocker.insert(
        "C:".to_string(),
        Fact::known(BitLockerState::Off, "test bitlocker query"),
    );
    let facts = SystemFacts {
        format_version: 1,
        gathered_unix: 1_700_004_000,
        boot_mode: Fact::known(BootMode::Uefi, "test firmware query"),
        secure_boot: Fact::known(false, "test secure boot query"),
        bitlocker,
        esp_files: Fact::known(list_esp_files(&esp_src).unwrap(), "test esp listing"),
        winre: Fact::known(
            WinReInfo {
                present: include_winre,
                location: include_winre
                    .then(|| "C:\\Windows\\System32\\Recovery\\Winre.wim".to_string()),
            },
            "test winre query",
        ),
        bcd: BcdCapture::not_included("test", "BCD is rebuilt by bcdboot during restore"),
    };
    attach_system_facts(&volume, &set_id, facts).unwrap();
    let manifest = read_set_manifest(&volume, &set_id).unwrap();
    let target = SystemRestoreTargetFacts {
        disk_id: "disk-1".to_string(),
        model: "Samsung SSD 990".to_string(),
        serial_suffix: "1234".to_string(),
        size_bytes: 256 * GIB,
        removable: false,
        firmware: Fact::known(BootMode::Uefi, "test firmware query"),
    };
    let options = SystemRestoreOptions {
        os_root: "osroot".to_string(),
        esp_root: "esproot".to_string(),
    };
    let plan = plan_system_restore(&manifest, &target, &options).unwrap();
    let fake_disk = base.join("fake-disk");
    let executor = SimulatedDiskExecutor {
        root: fake_disk.clone(),
    };
    executor.execute(&volume, &plan, &mut |_, _| {}).unwrap();
    (plan, fake_disk)
}

#[test]
fn a_faithful_simulated_restore_verifies() {
    let (plan, root) = simulated_restore("ok", true);
    let report = verify_system_restore(&plan, &root).unwrap();
    assert!(report.files_in_place(), "{report:#?}");
    assert_eq!(report.winre_image_present, Some(true));
    assert!(report.esp_boot_files.iter().all(|b| b.present));
    let win = report
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Windows)
        .unwrap();
    assert_eq!(win.files_checked, 2); // explorer.exe + the staged Winre.wim
    assert_eq!(win.files_ok, win.files_checked);
    // Registration is NOT concluded from files — even here.
    assert!(!report.boot_files_registered.is_known());
    assert!(report
        .boot_files_registered
        .unknown_reason
        .as_deref()
        .unwrap()
        .contains("cannot be concluded"));
    assert_eq!(
        report.boot_files_registered.source,
        "verify_system_restore: file inspection of the applied tree"
    );
}

#[test]
fn tampered_and_missing_files_are_named_per_partition() {
    let (plan, root) = simulated_restore("tamper", true);
    // Corrupt one OS file, delete one ESP file, delete the WinRE image.
    write(&root.join("windows/Windows/explorer.exe"), b"tampered");
    fs::remove_file(root.join("esp/EFI/Boot/bootx64.efi")).unwrap();
    fs::remove_file(root.join("winre/Recovery/WindowsRE/Winre.wim")).unwrap();

    let report = verify_system_restore(&plan, &root).unwrap();
    assert!(!report.files_in_place());
    let win = report
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Windows)
        .unwrap();
    assert_eq!(win.mismatched, vec!["Windows/explorer.exe".to_string()]);
    let esp = report
        .partitions
        .iter()
        .find(|p| p.role == PartitionRole::Esp)
        .unwrap();
    assert_eq!(esp.missing, vec!["EFI/Boot/bootx64.efi".to_string()]);
    let boot = report
        .esp_boot_files
        .iter()
        .find(|b| b.path == "EFI/Boot/bootx64.efi")
        .unwrap();
    assert!(!boot.present);
    assert_eq!(report.winre_image_present, Some(false));
}

#[test]
fn no_winre_plan_verifies_with_winre_absent_as_none() {
    let (plan, root) = simulated_restore("nowinre", false);
    assert!(plan.partition(PartitionRole::WinRe).is_none());
    let report = verify_system_restore(&plan, &root).unwrap();
    assert_eq!(report.winre_image_present, None);
    assert!(report.files_in_place(), "{report:#?}");
}

#[test]
fn verifying_the_wrong_root_fails_with_everything_missing() {
    let (plan, _root) = simulated_restore("wrongroot", true);
    let elsewhere =
        std::env::temp_dir().join(format!("safereturn-s5-verify-empty-{}", std::process::id()));
    let _ = fs::remove_dir_all(&elsewhere);
    let report = verify_system_restore(&plan, &elsewhere).unwrap();
    assert!(!report.files_in_place());
    assert!(report
        .partitions
        .iter()
        .all(|p| p.files_ok == 0 && p.files_checked == p.missing.len() as u64));
    assert_eq!(report.winre_image_present, Some(false));
    // And still: registration is a separate, unverified fact.
    assert!(!report.boot_files_registered.is_known());
}
