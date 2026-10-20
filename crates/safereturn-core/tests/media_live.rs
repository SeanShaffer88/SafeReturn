//! S4 live media build — the ONLY test that can erase a device, and
//! it is built to be unable to do so by accident:
//!
//! - Windows only (the file is empty elsewhere).
//! - `#[ignore]`d: `cargo test` never runs it; it takes an explicit
//!   `--ignored` invocation on the machine that owns the target.
//! - Inside, it still refuses unless SR_MEDIA_LIVE=1 is set (the
//!   executor enforces the same switch) AND the operator supplies
//!   the target facts + WinPE source through the environment:
//!     SR_MEDIA_LIVE=1
//!     SR_MEDIA_TARGET_SPEC=F:        (MakeWinPEMedia /UFD target)
//!     SR_MEDIA_TARGET_SIZE=<bytes>   (as enumerated for that device)
//!     SR_MEDIA_SERIAL_SUFFIX=<last 4 of the device serial>
//!     SR_WINPE_WIM=<path to winpe.wim from an ADK copype layout>
//!   Any missing value = clean skip, nothing written.
//!
//! This test has NEVER run. It is the entry point for the on-machine
//! media session in docs/S4_NOTES.md, not a CI check.
#![cfg(windows)]

use safereturn_core::media::*;
use safereturn_core::*;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[test]
#[ignore = "live media build: erases the SR_MEDIA_TARGET_SPEC device; run explicitly with SR_MEDIA_LIVE=1 and the SR_MEDIA_* / SR_WINPE_WIM env vars set"]
fn live_media_build_with_adk_executor() {
    if env(MEDIA_LIVE_ENV).as_deref() != Some("1") {
        eprintln!("skip: {MEDIA_LIVE_ENV} is not 1");
        return;
    }
    let (Some(target_spec), Some(size), Some(suffix), Some(wim)) = (
        env("SR_MEDIA_TARGET_SPEC"),
        env("SR_MEDIA_TARGET_SIZE"),
        env("SR_MEDIA_SERIAL_SUFFIX"),
        env("SR_WINPE_WIM"),
    ) else {
        eprintln!("skip: SR_MEDIA_TARGET_SPEC / SR_MEDIA_TARGET_SIZE / SR_MEDIA_SERIAL_SUFFIX / SR_WINPE_WIM not all set");
        return;
    };
    let wim_path = std::path::PathBuf::from(&wim);
    let wim_size = std::fs::metadata(&wim_path)
        .expect("SR_WINPE_WIM must point at a readable winpe.wim")
        .len();
    let facts = MediaFacts {
        target: MediaTargetFacts {
            disk_id: "live-test".into(),
            model: "live-test target".into(),
            serial_suffix: suffix,
            size_bytes: size.parse().expect("SR_MEDIA_TARGET_SIZE must be bytes"),
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: wim,
            wim_size_bytes: wim_size,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload: vec![],
    };
    let plan = plan_media(&facts, &Default::default()).expect("live facts must plan");
    let executor = WindowsAdkExecutor::new(target_spec);
    executor
        .execute(&plan, &mut |done, total| {
            eprintln!("media build step {done}/{total}");
        })
        .expect("live media build");
    eprintln!(
        "media built from plan {} — verify it with `safereturn media verify` before trusting it",
        plan.plan_id
    );
}
