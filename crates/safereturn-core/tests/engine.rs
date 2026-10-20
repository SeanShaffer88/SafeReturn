//! S2 acceptance tests for the engine API: plan-token restore discipline
//! and Level-2 File Rehearsal (see docs/S1_S2_NOTES.md).

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("safereturn-s2-{name}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn engine_with_backup(base: &Path) -> (Engine, String, PathBuf) {
    let src = base.join("src");
    fs::create_dir_all(src.join("docs")).unwrap();
    fs::write(src.join("docs/a.txt"), b"alpha").unwrap();
    fs::write(src.join("docs/b.txt"), b"bravo").unwrap();
    fs::write(src.join("c.txt"), b"charlie").unwrap();
    let vroot = base.join("volume");
    let (locked, _) = Volume::create(&vroot, "pw", 1_700_001_000).unwrap();
    let unlocked = locked.unlock_with_passphrase("pw").unwrap();
    let mut engine = Engine::new(unlocked);
    let mut events = Vec::new();
    let outcome = engine
        .start_backup("test", &[src.clone()], &mut |e| events.push(e))
        .unwrap();
    // Job event discipline: started first, finished (succeeded) last.
    assert!(matches!(events.first(), Some(Event::JobStarted { .. })));
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Succeeded,
            ..
        })
    ));
    (engine, outcome.manifest.set_id, src)
}

#[test]
fn restore_requires_the_exact_plan_token() {
    let base = tmp("token");
    let (mut engine, set_id, _src) = engine_with_backup(&base);
    let target = base.join("target");
    fs::create_dir_all(target.join("src/docs")).unwrap();
    // An existing, different a.txt — the plan must disclose it.
    fs::write(target.join("src/docs/a.txt"), b"OLD DIFFERENT").unwrap();

    let mut events = Vec::new();
    let plan = engine
        .plan_restore(&set_id, &target, None, &mut |e| events.push(e))
        .unwrap();
    assert_eq!(plan.overwrite_count, 1);
    assert!(plan.erase_warning_id.is_some());
    assert!(events.iter().any(|e| matches!(e, Event::RestorePlanned(_))));

    // No token / wrong token: refused, and the existing file is untouched.
    for bogus in ["", "not-a-token", &"0".repeat(64)] {
        let err = engine
            .start_restore(bogus, &mut |_| {})
            .err()
            .expect("bogus token must be refused");
        assert!(matches!(err, CoreError::InvalidPlanToken), "got: {err:?}");
        assert_eq!(
            fs::read(target.join("src/docs/a.txt")).unwrap(),
            b"OLD DIFFERENT",
            "a refused restore must write NOTHING"
        );
    }

    // The exact token executes the confirmed plan (all 3 files written:
    // a.txt replaced as previewed, b.txt and c.txt created).
    let outcome = engine.start_restore(&plan.plan_token, &mut |_| {}).unwrap();
    assert_eq!(outcome.files_written, 3);
    assert_eq!(
        fs::read(target.join("src/docs/a.txt")).unwrap(),
        b"alpha",
        "the planned overwrite must happen"
    );

    // Tokens are single-use.
    let err = engine
        .start_restore(&plan.plan_token, &mut |_| {})
        .err()
        .expect("reused token must be refused");
    assert!(matches!(err, CoreError::InvalidPlanToken));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn restore_plan_goes_stale_when_target_changes() {
    let base = tmp("stale");
    let (mut engine, set_id, _src) = engine_with_backup(&base);
    let target = base.join("target");
    fs::create_dir_all(&target).unwrap();

    let plan = engine
        .plan_restore(&set_id, &target, None, &mut |_| {})
        .unwrap();
    // Reality changes after the preview: a file appears where the plan
    // expected nothing, with content that differs from the backup.
    fs::create_dir_all(target.join("src/docs")).unwrap();
    fs::write(target.join("src/docs/b.txt"), b"SURPRISE").unwrap();

    let err = engine
        .start_restore(&plan.plan_token, &mut |_| {})
        .err()
        .expect("stale plan must be refused");
    assert!(matches!(err, CoreError::PlanStale { .. }), "got: {err:?}");
    // Nothing was written: the surprise file survives, the rest was not restored.
    assert_eq!(
        fs::read(target.join("src/docs/b.txt")).unwrap(),
        b"SURPRISE"
    );
    assert!(!target.join("src/c.txt").exists());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn low_level_restore_still_refuses_unapproved_overwrite() {
    let base = tmp("conflict");
    let (engine, set_id, _src) = engine_with_backup(&base);
    let target = base.join("target");
    fs::create_dir_all(target.join("src/docs")).unwrap();
    fs::write(target.join("src/docs/a.txt"), b"DO NOT TOUCH").unwrap();
    let mut noop = |_: u64, _: u64| {};
    let err = restore_set(
        engine.volume(),
        &set_id,
        &target,
        &HashSet::new(),
        &mut noop,
    )
    .unwrap_err();
    assert!(
        matches!(err, CoreError::RestoreConflict { .. }),
        "got: {err:?}"
    );
    assert_eq!(
        fs::read(target.join("src/docs/a.txt")).unwrap(),
        b"DO NOT TOUCH"
    );
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn file_rehearsal_passes_then_detects_damage() {
    let base = tmp("rehearsal");
    let (mut engine, set_id, _src) = engine_with_backup(&base);
    let chosen = vec!["src/docs/a.txt".to_string()];
    let report = engine
        .start_file_rehearsal(&set_id, &chosen, 2, false, &mut |_| {})
        .unwrap();
    assert!(
        report.passed(),
        "healthy set must rehearse clean: {report:?}"
    );
    assert_eq!(report.entries.len(), 3); // chosen + sample of 2 = whole set
    assert!(report.entries.iter().all(|e| e.passed));
    assert!(!report.sandbox.exists(), "sandbox is cleaned up by default");

    // Sampling is deterministic: same set + counts ⇒ same selection.
    let again = engine
        .start_file_rehearsal(&set_id, &[], 2, false, &mut |_| {})
        .unwrap();
    let first = engine
        .start_file_rehearsal(&set_id, &[], 2, false, &mut |_| {})
        .unwrap();
    let paths = |r: &FileRehearsalReport| {
        let mut p: Vec<String> = r.entries.iter().map(|e| e.path.clone()).collect();
        p.sort();
        p
    };
    assert_eq!(paths(&again), paths(&first));

    // Damage one chunk; the rehearsal of its file must fail and say why.
    let manifest = read_set_manifest(engine.volume(), &set_id).unwrap();
    let victim = manifest.file("src/docs/b.txt").unwrap().chunks[0].clone();
    let record = engine
        .volume()
        .root()
        .join("chunks")
        .join(&victim[..2])
        .join(&victim);
    let mut bytes = fs::read(&record).unwrap();
    let n = bytes.len();
    bytes[n - 3] ^= 0x01;
    fs::write(&record, &bytes).unwrap();

    let report = engine
        .start_file_rehearsal(
            &set_id,
            &["src/docs/b.txt".to_string()],
            0,
            false,
            &mut |_| {},
        )
        .unwrap();
    assert!(!report.passed());
    assert_eq!(report.entries.len(), 1);
    assert!(!report.entries[0].passed);
    assert!(
        report.entries[0].detail.contains(&victim) || report.entries[0].detail.contains("damaged"),
        "failure must name the damage, got: {}",
        report.entries[0].detail
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn list_backups_reports_manifest_facts() {
    let base = tmp("list");
    let (engine, set_id, _src) = engine_with_backup(&base);
    let mut events = Vec::new();
    let backups = engine.list_backups(&mut |e| events.push(e)).unwrap();
    assert_eq!(backups.len(), 1);
    assert_eq!(backups[0].backup_id, set_id);
    assert_eq!(backups[0].file_count, 3);
    assert!(matches!(events[0], Event::BackupList { .. }));
    let _ = fs::remove_dir_all(&base);
}
