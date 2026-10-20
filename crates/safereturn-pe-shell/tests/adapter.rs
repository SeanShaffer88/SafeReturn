//! S6 slice 3: the in-process transport adapter, driven with
//! contract messages exactly as the Win32 front-end drives it —
//! fake disk source, a real engine over a real encrypted system
//! set, and the simulation executor. Proves the whole PE restore
//! path (Hello → lists → guarded plan → simulated execute →
//! JobFinished) works over the wire types alone, and that the
//! SafeTarget override dance (refuse → acknowledge → plan) works
//! through adapter-held context.

use safereturn_contract::{DiskInfo, Event, JobOutcome, Request, ShellKind, CONTRACT_VERSION};
use safereturn_core::system::{BcdCapture, BitLockerState, BootMode, Fact, SystemFacts, WinReInfo};
use safereturn_core::*;
use safereturn_pe_shell::{derive_root_mapping, DiskSource, EngineAdapter, ExecutorChoice};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const GIB: u64 = 1024 * 1024 * 1024;
static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp_base(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-s6-adapter-{tag}-{}-{n}",
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

struct FakeDisks(Vec<DiskInfo>);

impl DiskSource for FakeDisks {
    fn list_disks(&self) -> Vec<DiskInfo> {
        self.0.clone()
    }
    fn disk_index(&self, disk_id: &str) -> Option<u32> {
        self.0
            .iter()
            .position(|d| d.disk_id == disk_id)
            .map(|i| i as u32)
    }
}

fn fake_disks() -> Vec<DiskInfo> {
    let mk = |id: &str, model: &str, serial: &str, size: u64, removable: bool| DiskInfo {
        disk_id: id.to_string(),
        model: model.to_string(),
        serial_suffix: serial.to_string(),
        size_bytes: size,
        free_bytes: 0,
        is_system_disk: false,
        is_removable: removable,
        warnings: Vec::new(),
    };
    vec![
        mk("physical-0", "Samsung SSD 990", "1234", 256 * GIB, false),
        mk("physical-1", "WD Elements", "5555", 2 * 1024 * GIB, true),
    ]
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

fn make_adapter(engine: Engine, base: &PathBuf, context: SafeTargetContext) -> EngineAdapter {
    EngineAdapter::new(
        engine,
        Box::new(FakeDisks(fake_disks())),
        context,
        Fact::known(BootMode::Uefi, "test firmware query"),
        ExecutorChoice::Fixed(Box::new(SimulatedDiskExecutor {
            root: base.join("fake-disk"),
        })),
    )
}

fn adapter_with_system_set(tag: &str) -> (EngineAdapter, PathBuf, String) {
    let (engine, base, set_id) = engine_with_system_set(tag);
    let adapter = make_adapter(engine, &base, SafeTargetContext::empty());
    (adapter, base, set_id)
}

fn hello() -> Request {
    Request::Hello {
        contract_version: CONTRACT_VERSION,
        shell: ShellKind::Win32Recovery,
        shell_version: "test".to_string(),
    }
}

#[test]
fn full_pe_restore_over_contract_messages() {
    let (mut adapter, base, set_id) = adapter_with_system_set("flow");

    let events = adapter.handle(hello());
    assert!(matches!(events.as_slice(), [Event::Welcome { .. }]));

    let events = adapter.handle(Request::ListBackups);
    match events.as_slice() {
        [Event::BackupList { backups }] => {
            assert_eq!(backups.len(), 1);
            assert_eq!(backups[0].backup_id, set_id);
        }
        other => panic!("expected BackupList, got {other:?}"),
    }

    let events = adapter.handle(Request::ListDisks);
    assert!(matches!(events.as_slice(), [Event::DiskList { disks }] if disks.len() == 2));

    // The internal target is non-removable: the guarded plan
    // demands the override first.
    let events = adapter.handle(Request::PlanSystemRestore {
        backup_id: set_id.clone(),
        target_disk_id: "physical-0".to_string(),
    });
    match events.as_slice() {
        [Event::Error {
            code, message_id, ..
        }] => {
            assert_eq!(code, "target.override_required");
            assert_eq!(message_id, "target.non_removable");
        }
        other => panic!("expected override demand, got {other:?}"),
    }

    adapter.acknowledge_warning("target.non_removable");
    let events = adapter.handle(Request::PlanSystemRestore {
        backup_id: set_id.clone(),
        target_disk_id: "physical-0".to_string(),
    });
    let token = match events.as_slice() {
        [Event::SystemRestorePlanned(plan)] => {
            assert_eq!(
                plan.erase_warning_id.as_deref(),
                Some("system_restore.will_erase_target")
            );
            assert!(plan.warnings.contains(&"target.non_removable".to_string()));
            plan.plan_token.clone()
        }
        other => panic!("expected SystemRestorePlanned, got {other:?}"),
    };

    let events = adapter.handle(Request::StartSystemRestore { plan_token: token });
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::JobFinished {
                outcome: JobOutcome::Succeeded,
                summary_id,
                ..
            } if summary_id == "result.system_restore_simulated"
        )),
        "events: {events:?}"
    );
    // The simulation really applied files through the adapter path.
    assert_eq!(
        fs::read(base.join("fake-disk/windows/Windows/explorer.exe")).unwrap(),
        b"explorer-bytes"
    );
}

#[test]
fn adapter_refuses_the_backup_disk_through_safetarget() {
    let (engine, base, set_id) = engine_with_system_set("guard");
    // The context names physical-1 (the removable "WD Elements")
    // as the disk holding the backup volume — targeting it for a
    // whole-PC restore must refuse through the engine's guard.
    let context = SafeTargetContext {
        backup_disk: Some(DiskIdentity::of(
            "physical-1",
            "WD Elements",
            "5555",
            2 * 1024 * GIB,
        )),
        ..Default::default()
    };
    let mut adapter = make_adapter(engine, &base, context);
    let events = adapter.handle(Request::PlanSystemRestore {
        backup_id: set_id.clone(),
        target_disk_id: "physical-1".to_string(),
    });
    match events.as_slice() {
        [Event::Error {
            code, message_id, ..
        }] => {
            assert_eq!(code, "target.refused");
            assert_eq!(message_id, "target.is_backup_disk");
        }
        other => panic!("expected SafeTarget refusal, got {other:?}"),
    }
    // The same disk is a fine target when it is NOT the backup
    // disk in context (the guard is selective, not a blanket ban):
    let (engine, base, set_id) = engine_with_system_set("guard-ok");
    let mut adapter = make_adapter(engine, &base, SafeTargetContext::empty());
    let events = adapter.handle(Request::PlanSystemRestore {
        backup_id: set_id.clone(),
        target_disk_id: "physical-1".to_string(),
    });
    assert!(
        matches!(events.as_slice(), [Event::SystemRestorePlanned(_)]),
        "events: {events:?}"
    );
}

#[test]
fn root_mapping_derivation_is_evidence_based() {
    let (adapter, _base, set_id) = adapter_with_system_set("roots");
    let manifest = read_set_manifest(adapter.engine().volume(), &set_id).unwrap();
    let options = derive_root_mapping(&manifest).unwrap();
    assert_eq!(options.os_root, "osroot");
    assert_eq!(options.esp_root, "esproot");
}

#[test]
fn unsupported_requests_and_bad_hello_are_named() {
    let (mut adapter, _base, _set_id) = adapter_with_system_set("misc");
    let events = adapter.handle(Request::Hello {
        contract_version: 999,
        shell: ShellKind::Win32Recovery,
        shell_version: "test".to_string(),
    });
    assert!(matches!(events.as_slice(), [Event::Incompatible { .. }]));
    let events = adapter.handle(Request::PlanMedia {
        target_disk_id: "physical-0".to_string(),
    });
    match events.as_slice() {
        [Event::Error { code, .. }] => assert_eq!(code, "shell.unsupported_in_pe"),
        other => panic!("expected unsupported error, got {other:?}"),
    }
    // CancelJob is accepted (and documented as unactionable until
    // the engine grows a cancellation primitive).
    let events = adapter.handle(Request::CancelJob {
        job_id: "job-1".to_string(),
    });
    assert!(events.is_empty());
}
