//! S5 live system restore — the entry point for the on-machine
//! restore session in docs/S5_NOTES.md. It is built to be unable
//! to erase anything by accident:
//!
//! - Windows only (the file is empty elsewhere).
//! - `#[ignore]`d: `cargo test` never runs it; it takes an explicit
//!   `--ignored` invocation on the machine that owns the target.
//! - Inside, it still refuses unless SR_RESTORE_LIVE=1 is set AND
//!   the operator supplies the volume, set, and target facts
//!   through the environment:
//!     SR_RESTORE_LIVE=1
//!     SR_RESTORE_VOLUME=<dir of the backup volume>
//!     SR_RESTORE_PASSPHRASE=<volume passphrase>
//!     SR_RESTORE_SET=<system set id on that volume>
//!     SR_RESTORE_DISK_INDEX=<diskpart disk number to ERASE>
//!     SR_RESTORE_DISK_SIZE=<bytes, as enumerated for that disk>
//!     SR_RESTORE_SERIAL_SUFFIX=<last 4 of the disk serial>
//!     SR_RESTORE_OS_ROOT=<set root display name of the OS volume>
//!     SR_RESTORE_ESP_ROOT=<set root display name of the ESP>
//!     SR_RESTORE_WORK_DIR=<dir for the rendered artifacts>
//!   Any missing value = clean skip, nothing written.
//!
//! As of S5 the WindowsDiskExecutor is a SKELETON: with all of the
//! above set, this test renders the plan's diskpart script and boot
//! command lines into SR_RESTORE_WORK_DIR and then expects the
//! executor's SystemRestoreExecutorNotReady refusal — proving the
//! gate, the plan flow, and the artifacts end-to-end while erasing
//! nothing. When the executor grows real disk operations in the
//! on-machine session, this test is where they get exercised.
//!
//! This test has NEVER run.
#![cfg(windows)]

use safereturn_core::system::{BootMode, Fact};
use safereturn_core::system_restore_exec::RESTORE_LIVE_ENV;
use safereturn_core::*;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[test]
#[ignore = "live system restore session entry point: run explicitly with SR_RESTORE_LIVE=1 and the SR_RESTORE_* env vars set (see file docs)"]
fn live_system_restore_windows_executor() {
    if env(RESTORE_LIVE_ENV).as_deref() != Some("1") {
        eprintln!("skip: {RESTORE_LIVE_ENV} is not 1");
        return;
    }
    let (
        Some(volume_dir),
        Some(passphrase),
        Some(set_id),
        Some(disk_index),
        Some(disk_size),
        Some(suffix),
        Some(os_root),
        Some(esp_root),
        Some(work_dir),
    ) = (
        env("SR_RESTORE_VOLUME"),
        env("SR_RESTORE_PASSPHRASE"),
        env("SR_RESTORE_SET"),
        env("SR_RESTORE_DISK_INDEX"),
        env("SR_RESTORE_DISK_SIZE"),
        env("SR_RESTORE_SERIAL_SUFFIX"),
        env("SR_RESTORE_OS_ROOT"),
        env("SR_RESTORE_ESP_ROOT"),
        env("SR_RESTORE_WORK_DIR"),
    )
    else {
        eprintln!("skip: SR_RESTORE_* env vars not all set");
        return;
    };
    let locked = Volume::open(std::path::PathBuf::from(&volume_dir))
        .expect("SR_RESTORE_VOLUME must be a SafeReturn volume");
    let volume = locked
        .unlock_with_passphrase(&passphrase)
        .expect("SR_RESTORE_PASSPHRASE must unlock the volume");
    let mut engine = Engine::new(volume);
    let target = SystemRestoreTargetFacts {
        disk_id: format!("disk-{disk_index}"),
        model: "live-test target".into(),
        serial_suffix: suffix,
        size_bytes: disk_size
            .parse()
            .expect("SR_RESTORE_DISK_SIZE must be bytes"),
        removable: false,
        // The live session runs in WinPE on the target machine; the
        // operator confirms the firmware mode by setting the facts
        // here — UEFI is the only mode S5 plans for.
        firmware: Fact::known(BootMode::Uefi, "live test operator confirmation"),
    };
    let options = SystemRestoreOptions { os_root, esp_root };
    let summary = engine
        .plan_system_restore(&set_id, &target, &options, &mut |_| {})
        .expect("live facts must plan");
    let executor = WindowsDiskExecutor {
        disk_index: disk_index
            .parse()
            .expect("SR_RESTORE_DISK_INDEX must be a number"),
        work_dir: std::path::PathBuf::from(&work_dir),
    };
    let err = engine
        .execute_system_restore(&summary.plan_token, &target, &executor, &mut |_| {})
        .expect_err("the S5 Windows executor is a skeleton and must refuse");
    assert!(
        matches!(err, CoreError::SystemRestoreExecutorNotReady { .. }),
        "expected the skeleton refusal, got: {err:?}"
    );
    eprintln!(
        "skeleton artifacts for plan {} rendered under {work_dir} — inspect safereturn-diskpart.txt before any real run",
        summary.plan_token
    );
}
