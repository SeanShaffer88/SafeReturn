//! S5 slice 2: engine system-restore discipline + executors.
//! - The diskpart script and boot command lines the Windows
//!   executor WOULD run are generated as pure data and pinned here
//!   byte-for-byte — a wrong script is the scariest failure mode in
//!   this feature, and this is the verification available without a
//!   machine.
//! - The simulation executor runs the FULL flow (plan token →
//!   drift check → file application from a real encrypted set →
//!   recorded post steps) against a directory-backed fake disk.
//! - Token rules mirror restore/media: single-use, consumed on any
//!   attempt, drift refuses before the executor is ever called.

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::system::{BcdCapture, BitLockerState, BootMode, Fact, SystemFacts, WinReInfo};
use safereturn_core::system_restore_exec::*;
use safereturn_core::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const GIB: u64 = 1024 * 1024 * 1024;

fn tmp_base(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-s5-exec-{tag}-{}-{n}",
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

/// Build a real encrypted volume holding a real system set (small
/// files with known contents), and an engine over it.
fn engine_with_system_set(tag: &str) -> (Engine, PathBuf, String) {
    let base = tmp_base(tag);
    let os_src = base.join("src").join("osroot");
    let esp_src = base.join("src").join("esproot");
    write(&os_src.join("Windows/explorer.exe"), b"explorer-bytes");
    write(
        &os_src.join("Windows/System32/Recovery/Winre.wim"),
        b"winre-image-bytes",
    );
    write(&os_src.join("Users/Sean/notes.txt"), b"hello restore");
    write(&esp_src.join("EFI/Boot/bootx64.efi"), b"bootx64");
    write(
        &esp_src.join("EFI/Microsoft/Boot/bootmgfw.efi"),
        b"bootmgfw",
    );
    write(&esp_src.join("EFI/Microsoft/Boot/BCD"), b"bcd-store");

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

fn target_facts() -> SystemRestoreTargetFacts {
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

fn core_plan(engine: &Engine, set_id: &str) -> SystemRestorePlan {
    let manifest = read_set_manifest(engine.volume(), set_id).unwrap();
    plan_system_restore(&manifest, &target_facts(), &options()).unwrap()
}

// ------------------------------------------------------- pure generators

#[test]
fn diskpart_script_is_exactly_the_documented_layout() {
    let (engine, _base, set_id) = engine_with_system_set("script");
    let plan = core_plan(&engine, &set_id);
    let script = diskpart_script(&plan, 0);
    // ESP content is a few dozen bytes → 300 MiB default.
    // Winre.wim is 17 bytes → 300 MiB minimum partition.
    // Windows: 262144 MiB total − 1 (front) − 300 − 16 − 300 − 1 (end).
    let expected = format!(
        "rem SafeReturn system restore - plan {plan_id}\n\
         rem Target disk 0: Samsung SSD 990 (serial ...1234), 274877906944 bytes\n\
         rem WARNING: this script ERASES disk 0 completely.\n\
         select disk 0\n\
         clean\n\
         convert gpt\n\
         rem Partition 1: EFI System Partition (ESP) - 300 MiB, FAT32\n\
         create partition efi size=300\n\
         format quick fs=fat32 label=\"System\"\n\
         assign letter=\"S\"\n\
         rem Partition 2: Microsoft Reserved (MSR) - 16 MiB\n\
         create partition msr size=16\n\
         rem Partition 3: Windows - 261526 MiB, NTFS\n\
         create partition primary size=261526\n\
         format quick fs=ntfs label=\"Windows\"\n\
         assign letter=\"W\"\n\
         rem Partition 4: Windows RE tools - 300 MiB, NTFS\n\
         create partition primary size=300\n\
         format quick fs=ntfs label=\"Windows RE tools\"\n\
         assign letter=\"R\"\n\
         set id=\"de94bba4-06d1-4d40-a16a-bfd50179d6ac\"\n\
         gpt attributes=0x8000000000000001\n\
         list volume\n\
         exit\n",
        plan_id = plan.plan_id
    );
    assert_eq!(script, expected);
    // A different disk index changes exactly the addressed disk.
    let script2 = diskpart_script(&plan, 3);
    assert!(script2.contains("select disk 3"));
    assert!(script2.contains("ERASES disk 3"));
}

#[test]
fn post_step_commands_are_exactly_the_documented_ones() {
    let (engine, _base, set_id) = engine_with_system_set("commands");
    let plan = core_plan(&engine, &set_id);
    assert_eq!(
        post_step_commands(&plan),
        vec![
            vec!["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"],
            vec![
                "reagentc",
                "/setreimage",
                "/path",
                "R:\\Recovery\\WindowsRE",
                "/target",
                "W:\\Windows"
            ],
            vec!["reagentc", "/enable"],
        ]
    );
}

// ------------------------------------------------------- engine + simulation

#[test]
fn simulated_restore_runs_the_full_flow() {
    let (mut engine, base, set_id) = engine_with_system_set("sim");
    let mut events: Vec<Event> = Vec::new();
    let summary = engine
        .plan_system_restore(&set_id, &target_facts(), &options(), &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert_eq!(
        summary.erase_warning_id.as_deref(),
        Some("system_restore.will_erase_target")
    );
    assert!(summary
        .warnings
        .contains(&"system_restore.bitlocker_not_restored".to_string()));
    assert!(matches!(
        events.last(),
        Some(Event::SystemRestorePlanned(_))
    ));

    let fake_disk = base.join("fake-disk");
    let executor = SimulatedDiskExecutor {
        root: fake_disk.clone(),
    };
    let mut events: Vec<Event> = Vec::new();
    let execution = engine
        .execute_system_restore(&summary.plan_token, &target_facts(), &executor, &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert!(execution.simulated);
    assert_eq!(execution.applied_root.as_deref(), Some(fake_disk.as_path()));
    assert_eq!(execution.files_written, 7); // 6 set files + WinRE placement
                                            // A simulation finishes under its OWN summary id — never the
                                            // real-restore one.
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished { outcome: JobOutcome::Succeeded, summary_id, .. })
        if summary_id == "result.system_restore_simulated"
    ));

    // Files landed byte-identical on their partitions.
    assert_eq!(
        fs::read(fake_disk.join("windows/Windows/explorer.exe")).unwrap(),
        b"explorer-bytes"
    );
    assert_eq!(
        fs::read(fake_disk.join("esp/EFI/Microsoft/Boot/bootmgfw.efi")).unwrap(),
        b"bootmgfw"
    );
    assert_eq!(
        fs::read(fake_disk.join("winre/Recovery/WindowsRE/Winre.wim")).unwrap(),
        b"winre-image-bytes"
    );

    // The restore log records the post steps as RECORDED, never as
    // executed, and the diskpart script is kept for inspection.
    let log: RestoreLog =
        serde_json::from_str(&fs::read_to_string(fake_disk.join(RESTORE_LOG_FILE)).unwrap())
            .unwrap();
    assert!(log.simulated);
    assert_eq!(log.post_steps.len(), 5); // bcdboot, setreimage, enable, 2 notices
    assert!(log
        .post_steps
        .iter()
        .all(|s| s.status == "recorded_simulated"));
    assert!(log.post_steps.iter().any(|s| s.command.as_ref()
        == Some(
            &["bcdboot", "W:\\Windows", "/s", "S:", "/f", "UEFI"]
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>()
        )));
    assert!(fake_disk.join(DISKPART_SCRIPT_FILE).exists());

    // The token is consumed: a second execute is an unknown token.
    let err = engine
        .execute_system_restore(&summary.plan_token, &target_facts(), &executor, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidPlanToken));
}

#[test]
fn drift_refuses_before_the_executor_and_consumes_the_token() {
    let (mut engine, base, set_id) = engine_with_system_set("drift");
    let summary = engine
        .plan_system_restore(&set_id, &target_facts(), &options(), &mut |_| {})
        .unwrap();
    let fake_disk = base.join("fake-disk");
    let executor = SimulatedDiskExecutor {
        root: fake_disk.clone(),
    };
    let mut drifted = target_facts();
    drifted.serial_suffix = "9999".to_string();
    let err = engine
        .execute_system_restore(&summary.plan_token, &drifted, &executor, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::SystemRestorePlanStale { .. }));
    assert_eq!(err.code(), "system_restore.plan_stale");
    // The executor never ran: no fake disk was created.
    assert!(!fake_disk.exists());
    // Consumed on the attempt: even with correct facts it is gone.
    let err = engine
        .execute_system_restore(&summary.plan_token, &target_facts(), &executor, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidPlanToken));

    // Firmware drift is drift too.
    let summary = engine
        .plan_system_restore(&set_id, &target_facts(), &options(), &mut |_| {})
        .unwrap();
    let mut drifted = target_facts();
    drifted.firmware = Fact::known(BootMode::Bios, "test firmware query");
    let err = engine
        .execute_system_restore(&summary.plan_token, &drifted, &executor, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::SystemRestorePlanStale { .. }));
}

#[test]
fn unknown_token_and_unsupported_executor_are_typed_errors() {
    let (mut engine, _base, set_id) = engine_with_system_set("tokens");
    let err = engine
        .execute_system_restore(
            "not-a-token",
            &target_facts(),
            &UnsupportedSystemRestoreExecutor,
            &mut |_| {},
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::SystemRestoreInvalidPlanToken));
    assert_eq!(err.code(), "system_restore.invalid_plan_token");

    // The platform real-disk executor: off Windows it is the
    // unsupported executor; on Windows it is the gated skeleton,
    // which refuses because SR_RESTORE_LIVE is not set in the test
    // environment. Either way the engine surfaces the typed error
    // and finishes the job as failed. (This assertion is
    // platform-shaped on purpose — the first version of this test
    // assumed the non-Windows answer and failed the Windows CI job
    // while every local gate was green.)
    let summary = engine
        .plan_system_restore(&set_id, &target_facts(), &options(), &mut |_| {})
        .unwrap();
    let executor = platform_system_restore_executor(0, _base.join("work"));
    let mut events: Vec<Event> = Vec::new();
    let err = engine
        .execute_system_restore(&summary.plan_token, &target_facts(), &*executor, &mut |e| {
            events.push(e)
        })
        .unwrap_err();
    #[cfg(windows)]
    assert!(
        matches!(err, CoreError::SystemRestoreLiveNotEnabled { .. }),
        "windows skeleton must refuse without SR_RESTORE_LIVE: {err:?}"
    );
    #[cfg(not(windows))]
    assert!(matches!(err, CoreError::UnsupportedPlatform { .. }));
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished { outcome: JobOutcome::Failed, summary_id, .. })
        if summary_id == "result.system_restore_failed"
    ));
}
