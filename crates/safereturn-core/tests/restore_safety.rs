//! Regression tests for untrusted manifests and file-restore preflight.

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::sets::{restore_entries, write_set_manifest};
use safereturn_core::*;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn fixture(name: &str) -> (PathBuf, Engine, SetManifest) {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-restore-safety-{name}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    let source = base.join("source");
    fs::create_dir_all(source.join("docs")).unwrap();
    fs::write(source.join("docs/a.txt"), b"alpha").unwrap();
    fs::write(source.join("docs/b.txt"), b"bravo").unwrap();
    fs::write(source.join("z.txt"), b"zulu").unwrap();
    let (locked, key) = Volume::create(base.join("volume"), "pw", 42).unwrap();
    let volume = locked.unlock_with_recovery_key(&key).unwrap();
    let manifest = backup_tree(&volume, "test", &[source], 42, &mut |_, _| {})
        .unwrap()
        .manifest;
    (base, Engine::new(volume), manifest)
}

fn save_under_id(volume: &UnlockedVolume, id: &str, manifest: &SetManifest) {
    let path = volume.root().join("sets").join(format!("{id}.json"));
    fs::write(path, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
}

#[test]
fn unsafe_manifest_paths_are_refused_before_restore_or_rehearsal() {
    let (base, mut engine, original) = fixture("paths");
    let target = base.join("target");
    let outside = base.join("outside.txt");
    fs::write(&outside, b"keep me").unwrap();
    let absolute = outside.to_string_lossy().to_string();
    let bad_paths = [
        "../outside.txt",
        "source/../../outside.txt",
        "/absolute/file.txt",
        "C:/Windows/file.txt",
        "source\\file.txt",
        "source/stream:secret",
        "source//file.txt",
        "source/./file.txt",
        "source/NUL.txt",
        "source/name. ",
        absolute.as_str(),
    ];
    for bad in bad_paths {
        let mut tampered = original.clone();
        tampered.files[0].path = bad.to_string();
        save_under_id(engine.volume(), &original.set_id, &tampered);
        let verify = verify_set(engine.volume(), &original.set_id, &mut |_, _| {}).unwrap();
        assert!(!verify.passed(), "Quick Check accepted {bad:?}");
        assert!(verify
            .file_failures
            .iter()
            .any(|failure| failure.path == bad && failure.reason == "unsafe_path"));
        let err = engine
            .plan_restore(&original.set_id, &target, None, &mut |_| {})
            .unwrap_err();
        assert!(
            matches!(err, CoreError::UnsafeRestorePath { .. }),
            "{bad}: {err:?}"
        );
        assert_eq!(err.code(), "restore.unsafe_path");
        assert!(matches!(
            restore_set(
                engine.volume(),
                &original.set_id,
                &target,
                &HashSet::new(),
                &mut |_, _| {}
            ),
            Err(CoreError::UnsafeRestorePath { .. })
        ));
        assert!(matches!(
            restore_file(
                engine.volume(),
                &original.set_id,
                bad,
                &target.join("single"),
                false
            ),
            Err(CoreError::UnsafeRestorePath { .. })
        ));
        assert!(matches!(
            engine.start_file_rehearsal(
                &original.set_id,
                &[bad.to_string()],
                0,
                false,
                &mut |_| {}
            ),
            Err(CoreError::UnsafeRestorePath { .. })
        ));
        assert!(!target.exists(), "unsafe path created the target: {bad:?}");
        assert_eq!(fs::read(&outside).unwrap(), b"keep me");
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn duplicate_case_and_file_directory_aliases_refuse_entire_scope() {
    let (base, mut engine, original) = fixture("aliases");
    let target = base.join("target");
    for (first, second, code) in [
        ("source/docs/a.txt", "source/docs/a.txt", "duplicate_path"),
        ("source/docs/A.txt", "source/docs/a.txt", "conflicting_path"),
        ("source/docs/a", "source/docs/A/child", "conflicting_path"),
    ] {
        let mut changed = original.clone();
        changed.files[0].path = first.to_string();
        changed.files[1].path = second.to_string();
        save_under_id(engine.volume(), &original.set_id, &changed);
        let check = verify_set(engine.volume(), &original.set_id, &mut |_, _| {}).unwrap();
        assert!(!check.passed());
        assert!(check
            .file_failures
            .iter()
            .any(|failure| failure.reason == code));
        // Even a single-file request cannot choose one ambiguous entry.
        assert!(matches!(
            engine.plan_restore(&original.set_id, &target, Some(first), &mut |_| {}),
            Err(CoreError::UnsafeRestorePath { .. })
        ));
        assert!(matches!(
            restore_files(
                engine.volume(),
                &changed.files,
                &target,
                &HashSet::new(),
                &mut |_, _| {}
            ),
            Err(CoreError::UnsafeRestorePath { .. })
        ));
        assert!(!target.exists());
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn set_ids_cannot_select_or_publish_files_outside_the_sets_directory() {
    let (base, engine, original) = fixture("id");
    let outside = engine.volume().root().join("outside.json");
    fs::write(&outside, b"do not replace").unwrap();
    for id in ["../outside", "/absolute", "C:relative", "a\\b", "", "NUL"] {
        assert!(matches!(
            read_set_manifest(engine.volume(), id),
            Err(CoreError::InvalidSetManifest { .. })
        ));
        let mut altered = original.clone();
        altered.set_id = id.to_string();
        assert!(matches!(
            write_set_manifest(engine.volume(), &altered),
            Err(CoreError::InvalidSetManifest { .. })
        ));
        assert_eq!(fs::read(&outside).unwrap(), b"do not replace");
    }
    let mut changed = original.clone();
    changed.set_id = "different-valid-id".to_string();
    save_under_id(engine.volume(), &original.set_id, &changed);
    assert!(matches!(
        read_set_manifest(engine.volume(), &original.set_id),
        Err(CoreError::InvalidSetManifest { .. })
    ));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn different_content_changing_to_other_different_content_invalidates_plan() {
    let (base, mut engine, manifest) = fixture("drift");
    let target = base.join("target");
    let a = target.join("source/docs/a.txt");
    fs::create_dir_all(a.parent().unwrap()).unwrap();
    fs::write(&a, b"old version").unwrap();
    let plan = engine
        .plan_restore(&manifest.set_id, &target, None, &mut |_| {})
        .unwrap();
    assert_eq!(plan.overwrite_count, 1);
    fs::write(&a, b"newer version").unwrap();
    let error = engine
        .start_restore(&plan.plan_token, &mut |_| {})
        .unwrap_err();
    assert!(matches!(error, CoreError::PlanStale { .. }));
    assert_eq!(fs::read(&a).unwrap(), b"newer version");
    assert!(!target.join("source/docs/b.txt").exists());
    assert!(matches!(
        engine.start_restore(&plan.plan_token, &mut |_| {}),
        Err(CoreError::InvalidPlanToken)
    ));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn changes_during_a_job_stop_later_writes_and_report_partial_progress() {
    let (base, mut engine, manifest) = fixture("mid-job");
    let target = base.join("target");
    let a = target.join("source/docs/a.txt");
    let b = target.join("source/docs/b.txt");
    fs::create_dir_all(a.parent().unwrap()).unwrap();
    fs::write(&a, b"old a").unwrap();
    fs::write(&b, b"old b").unwrap();
    let plan = engine
        .plan_restore(&manifest.set_id, &target, None, &mut |_| {})
        .unwrap();
    assert_eq!(plan.overwrite_count, 2);
    let mut events = Vec::new();
    let error = engine
        .start_restore(&plan.plan_token, &mut |event| {
            if matches!(event, Event::JobProgress { done: 1, .. }) {
                fs::write(&b, b"changed while restoring").unwrap();
            }
            events.push(event);
        })
        .unwrap_err();
    assert!(matches!(error, CoreError::RestoreTargetChanged { .. }));
    assert!(error
        .to_string()
        .contains("Earlier files may already have been restored"));
    assert_eq!(fs::read(&a).unwrap(), b"alpha");
    assert_eq!(fs::read(&b).unwrap(), b"changed while restoring");
    assert!(!target.join("source/z.txt").exists());
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            ..
        })
    ));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn unrelated_old_temp_name_survives_and_untrusted_size_does_not_allocate_a_file() {
    let (base, mut engine, manifest) = fixture("stage");
    let target = base.join("target");
    let a = target.join("a.txt");
    let old_temp = a.with_extension("safereturn-tmp");
    fs::create_dir_all(&target).unwrap();
    fs::write(&old_temp, b"unrelated existing file").unwrap();
    let plan = engine
        .plan_restore(
            &manifest.set_id,
            &target,
            Some("source/docs/a.txt"),
            &mut |_| {},
        )
        .unwrap();
    // Single-file plans restore under the selected directory directly.
    assert_eq!(plan.overwrite_count, 0);
    engine.start_restore(&plan.plan_token, &mut |_| {}).unwrap();
    assert_eq!(fs::read(target.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(&old_temp).unwrap(), b"unrelated existing file");

    let mut huge = manifest.files[0].clone();
    huge.size = u64::MAX;
    let out = base.join("huge-result");
    let error = restore_entries(
        engine.volume(),
        &[(huge, out.clone())],
        &HashSet::new(),
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(error, CoreError::ChunkCorrupt { .. }), "{error:?}");
    assert!(!out.exists());
    assert!(!fs::read_dir(&base).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".safereturn-")));
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn existing_symlinked_parents_and_files_are_refused() {
    use std::os::unix::fs::symlink;
    let (base, mut engine, manifest) = fixture("links");
    let target = base.join("target");
    let outside = base.join("outside");
    fs::create_dir_all(outside.join("docs")).unwrap();
    fs::write(outside.join("docs/a.txt"), b"outside sentinel").unwrap();
    fs::create_dir_all(&target).unwrap();
    symlink(&outside, target.join("source")).unwrap();
    assert!(matches!(
        engine.plan_restore(&manifest.set_id, &target, None, &mut |_| {}),
        Err(CoreError::UnsafeRestoreDestination { .. })
    ));
    assert!(matches!(
        restore_set(
            engine.volume(),
            &manifest.set_id,
            &target,
            &HashSet::new(),
            &mut |_, _| {}
        ),
        Err(CoreError::UnsafeRestoreDestination { .. })
    ));
    assert_eq!(
        fs::read(outside.join("docs/a.txt")).unwrap(),
        b"outside sentinel"
    );
    assert!(!outside.join("docs/b.txt").exists());
    fs::remove_file(target.join("source")).unwrap();
    fs::create_dir_all(target.join("source/docs")).unwrap();
    symlink(outside.join("docs/a.txt"), target.join("source/docs/a.txt")).unwrap();
    assert!(matches!(
        engine.plan_restore(&manifest.set_id, &target, None, &mut |_| {}),
        Err(CoreError::UnsafeRestoreDestination { .. })
    ));
    fs::remove_file(target.join("source/docs/a.txt")).unwrap();
    symlink(
        outside.join("missing.txt"),
        target.join("source/docs/a.txt"),
    )
    .unwrap();
    assert!(matches!(
        engine.plan_restore(&manifest.set_id, &target, None, &mut |_| {}),
        Err(CoreError::UnsafeRestoreDestination { .. })
    ));
    assert!(!outside.join("missing.txt").exists());
    let _ = fs::remove_dir_all(base);
}

#[cfg(windows)]
#[test]
fn existing_windows_junction_parent_is_refused() {
    let (base, mut engine, manifest) = fixture("junction");
    let target = base.join("target");
    let outside = base.join("outside");
    fs::create_dir_all(outside.join("docs")).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::write(outside.join("docs/a.txt"), b"outside sentinel").unwrap();
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(target.join("source"))
        .arg(&outside)
        .status()
        .unwrap();
    assert!(status.success(), "could not create a test junction");
    assert!(matches!(
        engine.plan_restore(&manifest.set_id, &target, None, &mut |_| {}),
        Err(CoreError::UnsafeRestoreDestination { .. })
    ));
    assert_eq!(
        fs::read(outside.join("docs/a.txt")).unwrap(),
        b"outside sentinel"
    );
    assert!(!outside.join("docs/b.txt").exists());
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn newly_captured_unportable_recorded_path_is_not_published() {
    let (base, engine, _) = fixture("capture-path");
    let source = base.join("new-source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file:stream"), b"must remain intact").unwrap();
    let before = list_set_ids(engine.volume()).unwrap();
    let err = backup_tree(
        engine.volume(),
        "bad path",
        &[source.clone()],
        43,
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::BackupVerificationFailed { .. }));
    assert!(err.to_string().contains("unsafe_path"));
    assert_eq!(list_set_ids(engine.volume()).unwrap(), before);
    assert_eq!(
        fs::read(source.join("file:stream")).unwrap(),
        b"must remain intact"
    );
    let _ = fs::remove_dir_all(base);
}
