//! S4 slice 2: engine media plan-token discipline — the same rules
//! as restore plans, for an operation that ERASES a device:
//! single-use tokens, consumed on any attempt, target-fact drift
//! refuses before the executor is ever called.

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::media::*;
use safereturn_core::*;
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
const GIB: u64 = 1024 * 1024 * 1024;
const MIB: u64 = 1024 * 1024;

fn tmp_engine() -> (Engine, PathBuf) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("safereturn-s4-media-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let (locked, _) = Volume::create(base.join("volume"), "pw", 1_700_002_000).unwrap();
    let unlocked = locked.unlock_with_passphrase("pw").unwrap();
    (Engine::new(unlocked), base)
}

fn facts() -> MediaFacts {
    MediaFacts {
        target: MediaTargetFacts {
            disk_id: "disk-3".into(),
            model: "USB Flash Drive".into(),
            serial_suffix: "X7K2".into(),
            size_bytes: 16 * GIB,
            removable: true,
        },
        winpe: WinPeSourceFacts {
            wim_path: "C:\\WinPE_amd64\\media\\sources\\boot.wim".into(),
            wim_size_bytes: 400 * MIB,
            present: true,
            adk_version: None,
        },
        drivers: vec![],
        payload: vec![PayloadFact {
            source_path: "C:\\app\\safereturn-pe.exe".into(),
            dest_rel: "safereturn/safereturn-pe.exe".into(),
            size_bytes: 50 * MIB,
            sha256: "b".repeat(64),
        }],
    }
}

/// Records every plan it was asked to execute; can be told to fail.
struct RecordingExecutor {
    executed: RefCell<Vec<String>>,
    fail: bool,
}

impl RecordingExecutor {
    fn new() -> Self {
        Self {
            executed: RefCell::new(Vec::new()),
            fail: false,
        }
    }
    fn failing() -> Self {
        Self {
            executed: RefCell::new(Vec::new()),
            fail: true,
        }
    }
    fn calls(&self) -> Vec<String> {
        self.executed.borrow().clone()
    }
}

impl MediaExecutor for RecordingExecutor {
    fn execute(&self, plan: &MediaPlan, progress: &mut dyn FnMut(u64, u64)) -> Result<()> {
        self.executed.borrow_mut().push(plan.plan_id.clone());
        progress(1, 1);
        if self.fail {
            return Err(CoreError::Io {
                path: None,
                source: std::io::Error::other("executor told to fail by the test"),
            });
        }
        Ok(())
    }
}

#[test]
fn plan_then_create_executes_the_confirmed_plan_once() {
    let (mut engine, _base) = tmp_engine();
    let f = facts();
    let mut events = Vec::new();
    let summary = engine
        .plan_media(&f, &Default::default(), &mut |e| events.push(e))
        .unwrap();
    // MediaPlanned was emitted, and the summary carries the erase
    // warning — always, for media.
    assert!(matches!(events.last(), Some(Event::MediaPlanned(_))));
    assert_eq!(
        summary.erase_warning_id.as_deref(),
        Some("media.will_erase_target")
    );
    assert_eq!(summary.target_disk_id, "disk-3");
    assert_eq!(summary.boot_partition_bytes, 563 * MIB);

    let exec = RecordingExecutor::new();
    let mut events = Vec::new();
    let plan = engine
        .create_media(&summary.plan_token, &f.target, &exec, &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert_eq!(exec.calls(), vec![plan.plan_id.clone()]);
    assert!(matches!(events.first(), Some(Event::JobStarted { .. })));
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Succeeded,
            ..
        })
    ));

    // The token is consumed: a second create is an unknown token and
    // the executor is not called again.
    let err = engine
        .create_media(&summary.plan_token, &f.target, &exec, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaInvalidPlanToken));
    assert_eq!(exec.calls().len(), 1);
}

#[test]
fn unknown_token_is_refused_and_executor_never_runs() {
    let (mut engine, _base) = tmp_engine();
    let exec = RecordingExecutor::new();
    let err = engine
        .create_media("deadbeef", &facts().target, &exec, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaInvalidPlanToken));
    assert_eq!(err.code(), "media.invalid_plan_token");
    assert!(exec.calls().is_empty());
}

#[test]
fn target_drift_refuses_as_stale_and_consumes_the_token() {
    let (mut engine, _base) = tmp_engine();
    let f = facts();
    let summary = engine
        .plan_media(&f, &Default::default(), &mut |_| {})
        .unwrap();
    let exec = RecordingExecutor::new();

    // A different-sized device is attached at execute time.
    let mut drifted = f.target.clone();
    drifted.size_bytes = 32 * GIB;
    let err = engine
        .create_media(&summary.plan_token, &drifted, &exec, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaPlanStale { .. }));
    assert_eq!(err.code(), "media.plan_stale");
    assert!(exec.calls().is_empty());

    // Consumed on the attempt: even with the right facts now, the
    // token is gone — the user must see a fresh plan.
    let err = engine
        .create_media(&summary.plan_token, &f.target, &exec, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaInvalidPlanToken));

    // Serial-suffix drift (a different physical stick) is stale too.
    let summary2 = engine
        .plan_media(&f, &Default::default(), &mut |_| {})
        .unwrap();
    let mut other_stick = f.target.clone();
    other_stick.serial_suffix = "Q9Z3".into();
    let err = engine
        .create_media(&summary2.plan_token, &other_stick, &exec, &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaPlanStale { .. }));
    assert!(exec.calls().is_empty());
}

#[test]
fn executor_failure_is_a_failed_job_not_a_success() {
    let (mut engine, _base) = tmp_engine();
    let f = facts();
    let summary = engine
        .plan_media(&f, &Default::default(), &mut |_| {})
        .unwrap();
    let exec = RecordingExecutor::failing();
    let mut events = Vec::new();
    let err = engine
        .create_media(&summary.plan_token, &f.target, &exec, &mut |e| {
            events.push(e)
        })
        .unwrap_err();
    assert!(matches!(err, CoreError::Io { .. }));
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            ..
        })
    ));
}

#[test]
fn unsupported_executor_surfaces_the_typed_platform_error() {
    let (mut engine, _base) = tmp_engine();
    let f = facts();
    let summary = engine
        .plan_media(&f, &Default::default(), &mut |_| {})
        .unwrap();
    let err = engine
        .create_media(
            &summary.plan_token,
            &f.target,
            &UnsupportedExecutor,
            &mut |_| {},
        )
        .unwrap_err();
    assert!(matches!(err, CoreError::UnsupportedPlatform { .. }));
    assert_eq!(err.code(), "core.unsupported_platform");
}

#[test]
fn planning_refusals_pass_through_the_engine() {
    let (mut engine, _base) = tmp_engine();
    let mut f = facts();
    f.target.removable = false;
    let err = engine
        .plan_media(&f, &Default::default(), &mut |_| {})
        .unwrap_err();
    assert!(matches!(err, CoreError::MediaTargetNotRemovable));
}
