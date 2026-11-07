//! Windows media-executor safety check. This is deliberately NOT a
//! live-media test: no real disk, WinPE source, or ADK is required.
//! The former destructive test must not be restored until the target
//! identity and protected-disk requirements in docs/S4_NOTES.md have
//! been implemented and independently verified.
#![cfg(windows)]

use safereturn_core::*;
use std::fs;

#[test]
fn exported_windows_executor_refuses_a_valid_plan_without_writing() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "safereturn-media-windows-fence-{}-{unique}",
        std::process::id()
    ));
    fs::create_dir(&base).unwrap();
    let marker = base.join("untouched.txt");
    fs::write(&marker, b"untouched").unwrap();
    let facts = MediaFacts {
        target: MediaTargetFacts {
            disk_id: "synthetic".into(),
            model: "synthetic".into(),
            serial_suffix: "1234".into(),
            size_bytes: 16 * 1024 * 1024 * 1024,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "not-a-real-wim".into(),
            wim_size_bytes: 4096,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload: vec![],
    };
    let mut plan = plan_media(&facts, &Default::default()).unwrap();
    // Keep this test non-destructive even if the fence is accidentally
    // removed: no MakeMedia step, no real selector, and no ADK here.
    plan.steps = vec![MediaStep::Copype {
        arch: "amd64".into(),
    }];
    let executor =
        WindowsAdkExecutor::new("NOT-A-DEVICE".into()).with_adk_root(base.join("missing-adk"));
    let mut progress = 0;
    let err = executor
        .execute(&plan, &mut |_, _| progress += 1)
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaExecutorNotReady));
    assert_eq!(progress, 0);
    assert_eq!(fs::read(marker).unwrap(), b"untouched");
    fs::remove_dir_all(base).unwrap();
}
