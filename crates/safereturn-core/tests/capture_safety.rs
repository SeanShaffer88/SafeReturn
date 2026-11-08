//! Source traversal checks are point-in-time safeguards, not a filesystem sandbox.

use safereturn_contract::Event;
#[cfg(unix)]
use safereturn_contract::JobOutcome;
use safereturn_core::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-capture-safety-{name}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base
}

fn volume(base: &Path) -> UnlockedVolume {
    let (locked, key) = Volume::create(base.join("volume"), "pw", 42).unwrap();
    locked.unlock_with_recovery_key(&key).unwrap()
}

struct BoundarySource {
    resolved: PathBuf,
    boundary: PathBuf,
}

impl CaptureSource for BoundarySource {
    fn resolve_root(&self, _: &Path) -> Result<PathBuf> {
        Ok(self.resolved.clone())
    }

    fn inspection_boundary(&self) -> Option<&Path> {
        Some(&self.boundary)
    }

    fn capture_mode(&self) -> CaptureMode {
        CaptureMode::Live
    }
}

#[test]
fn custom_capture_cannot_resolve_outside_its_claimed_boundary() {
    let base = tmp("boundary");
    let anchor = base.join("device");
    fs::create_dir_all(anchor.join("child")).unwrap();
    let outside = base.join("outside.txt");
    fs::write(&outside, b"outside sentinel").unwrap();
    let volume = volume(&base);
    // Check both a completely unrelated root and a lexical .. escape.
    for resolved in [outside.clone(), anchor.join("child/../../outside.txt")] {
        let source = BoundarySource {
            resolved,
            boundary: anchor.clone(),
        };
        let error = backup_tree_with_source(
            &volume,
            &source,
            "unsafe",
            &[PathBuf::from("logical.txt")],
            100,
            &mut |_, _| {},
        )
        .unwrap_err();
        assert_eq!(error.code(), "backup.unsafe_source");
        assert!(matches!(error, CoreError::UnsafeBackupSource { .. }));
        assert!(error.to_string().contains("boundary"));
        assert!(list_set_ids(&volume).unwrap().is_empty());
        assert!(volume.chunk_ids_on_disk().unwrap().is_empty());
        assert_eq!(fs::read(&outside).unwrap(), b"outside sentinel");
    }
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn selected_file_directory_dangling_and_ancestor_links_are_refused_before_copying() {
    use std::os::unix::fs::symlink;

    let base = tmp("root-links");
    let good = base.join("good");
    let outside = base.join("outside");
    fs::create_dir_all(&good).unwrap();
    fs::create_dir_all(outside.join("subdir")).unwrap();
    fs::write(good.join("first.txt"), b"must not get copied").unwrap();
    fs::write(outside.join("subdir/secret.txt"), b"outside sentinel").unwrap();
    symlink(outside.join("subdir/secret.txt"), base.join("file-link")).unwrap();
    symlink(outside.join("subdir"), base.join("dir-link")).unwrap();
    symlink(base.join("missing"), base.join("dangling")).unwrap();
    symlink(&outside, base.join("ancestor")).unwrap();

    let volume = volume(&base);
    let old_source = base.join("old");
    fs::create_dir_all(&old_source).unwrap();
    fs::write(old_source.join("old.txt"), b"previous backup").unwrap();
    let old = backup_tree(&volume, "old", &[old_source], 1, &mut |_, _| {})
        .unwrap()
        .manifest;
    let sets_before = list_set_ids(&volume).unwrap();
    let chunks_before = volume.chunk_ids_on_disk().unwrap();
    let old_manifest = fs::read(
        volume
            .root()
            .join("sets")
            .join(format!("{}.json", old.set_id)),
    )
    .unwrap();
    // Construct a relative path without changing the process-wide cwd.
    let mut relative_link = PathBuf::new();
    for component in std::env::current_dir().unwrap().components() {
        if matches!(component, std::path::Component::Normal(_)) {
            relative_link.push("..");
        }
    }
    relative_link.push(base.strip_prefix("/").unwrap());
    relative_link.push("file-link");

    for selected in [
        base.join("file-link"),
        relative_link,
        base.join("dir-link"),
        // Trailing separators and dot components must not make lstat
        // follow a selected directory link.
        PathBuf::from(format!("{}/", base.join("dir-link").display())),
        base.join("dir-link/."),
        base.join("dangling"),
        base.join("ancestor/subdir/secret.txt"),
        base.join("ancestor/../outside/subdir/secret.txt"),
    ] {
        let mut progress = Vec::new();
        let error = backup_tree(
            &volume,
            "refused",
            &[good.clone(), selected.clone()],
            2,
            &mut |done, total| progress.push((done, total)),
        )
        .unwrap_err();
        assert_eq!(
            error.code(),
            "backup.unsafe_source",
            "{selected:?}: {error:?}"
        );
        assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
        assert!(error.to_string().contains("symbolic link"), "{error}");
        assert!(error.to_string().contains("No backup set was saved"));
        assert!(progress.is_empty());
        assert_eq!(list_set_ids(&volume).unwrap(), sets_before);
        assert_eq!(volume.chunk_ids_on_disk().unwrap(), chunks_before);
        assert_eq!(
            fs::read(outside.join("subdir/secret.txt")).unwrap(),
            b"outside sentinel"
        );
        assert_eq!(
            fs::read(good.join("first.txt")).unwrap(),
            b"must not get copied"
        );
    }
    assert_eq!(
        fs::read(
            volume
                .root()
                .join("sets")
                .join(format!("{}.json", old.set_id))
        )
        .unwrap(),
        old_manifest
    );
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn skipped_children_are_reported_and_cycles_or_external_content_are_not_followed() {
    use std::os::unix::fs::symlink;

    let base = tmp("children");
    let source = base.join("source");
    let outside = base.join("outside");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(source.join("nested/keep.txt"), b"inside").unwrap();
    fs::write(
        outside.join("secret.txt"),
        b"outside data must not be captured",
    )
    .unwrap();
    symlink(outside.join("secret.txt"), source.join("linked-file")).unwrap();
    symlink(&outside, source.join("linked-directory")).unwrap();
    symlink("missing-target", source.join("dangling")).unwrap();
    symlink(&source, source.join("nested/cycle")).unwrap();
    let _socket = std::os::unix::net::UnixListener::bind(source.join("socket")).unwrap();

    let mut engine = Engine::new(volume(&base));
    let mut events = Vec::new();
    let outcome = engine
        .start_backup("links", &[source.clone()], &mut |e| events.push(e))
        .unwrap();
    assert_eq!(outcome.manifest.files.len(), 1);
    assert!(outcome.manifest.file("source/nested/keep.txt").is_some());
    let paths: Vec<_> = outcome
        .manifest
        .skipped
        .iter()
        .map(|s| s.path.as_str())
        .collect();
    for expected in [
        "source/linked-file",
        "source/linked-directory",
        "source/dangling",
        "source/nested/cycle",
        "source/socket",
    ] {
        assert!(paths.contains(&expected), "missing {expected}: {paths:?}");
    }
    assert_eq!(paths.len(), 5);
    for skipped in &outcome.manifest.skipped {
        if skipped.path == "source/socket" {
            assert!(skipped.reason.contains("not a regular file"));
        } else {
            assert!(skipped.reason.contains("not followed"));
        }
    }
    assert!(!engine
        .volume()
        .chunk_exists(&sha256_hex(b"outside data must not be captured")));
    assert!(matches!(events.last(), Some(Event::JobFinished {
        outcome: JobOutcome::Succeeded, summary_id, ..
    }) if summary_id == BACKUP_WITH_SKIPS_SUMMARY_ID));
    let stored = read_set_manifest(engine.volume(), &outcome.manifest.set_id).unwrap();
    assert_eq!(stored.skipped, outcome.manifest.skipped);
    assert!(verify_set(engine.volume(), &stored.set_id, &mut |_, _| {})
        .unwrap()
        .passed());

    // A clean backup retains the original, unqualified success summary.
    let clean = base.join("clean");
    fs::create_dir_all(&clean).unwrap();
    fs::write(clean.join("ok.txt"), b"clean").unwrap();
    events.clear();
    let result = engine
        .start_backup("clean", &[clean], &mut |e| events.push(e))
        .unwrap();
    assert!(result.manifest.skipped.is_empty());
    assert!(matches!(events.last(), Some(Event::JobFinished {
        outcome: JobOutcome::Succeeded, summary_id, ..
    }) if summary_id == "result.backup_succeeded"));
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn mapped_roots_check_logical_descendants_and_keep_device_anchor_private() {
    use std::os::unix::fs::symlink;

    let base = tmp("mapped");
    let snapshot = base.join("snapshot-device");
    let outside = base.join("outside");
    fs::create_dir_all(snapshot.join("Docs")).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), b"outside").unwrap();
    fs::write(snapshot.join("Docs/keep.txt"), b"inside").unwrap();
    symlink(&outside, snapshot.join("Docs/redirect")).unwrap();
    let volume = volume(&base);
    let mapped = MappedSource::new("C:", snapshot.clone());

    let selected = PathBuf::from(r"C:\Docs\redirect\secret.txt");
    let error = backup_tree_with_source(
        &volume,
        &mapped,
        "bad",
        &[selected.clone()],
        1,
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
    assert!(!error.to_string().contains("snapshot-device"));
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert!(volume.chunk_ids_on_disk().unwrap().is_empty());

    let mut events = Vec::new();
    let mut engine = Engine::new(volume);
    let outcome = engine
        .start_backup_with_source("mapped", &[PathBuf::from(r"C:\Docs")], &mapped, &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert_eq!(outcome.manifest.capture_mode, CaptureMode::VssSnapshot);
    assert!(outcome.manifest.file("docs/keep.txt").is_some());
    assert_eq!(outcome.manifest.skipped.len(), 1);
    assert_eq!(outcome.manifest.skipped[0].path, "docs/redirect");
    assert!(!serde_json::to_string(&outcome.manifest)
        .unwrap()
        .contains("snapshot-device"));
    assert!(
        matches!(events.last(), Some(Event::JobFinished { summary_id, .. })
        if summary_id == BACKUP_WITH_SKIPS_SUMMARY_ID)
    );
    assert_eq!(fs::read(outside.join("secret.txt")).unwrap(), b"outside");
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn mapped_device_anchor_is_trusted_for_descendants_but_checked_when_selected() {
    use std::os::unix::fs::symlink;

    let base = tmp("trusted-anchor");
    let device = base.join("device-link");
    let actual = base.join("actual-snapshot");
    fs::create_dir_all(actual.join("Docs")).unwrap();
    fs::write(actual.join("Docs/file.txt"), b"trusted data").unwrap();
    symlink(&actual, &device).unwrap();
    let mapped = MappedSource::new(r"C:\", device);
    let volume = volume(&base);

    // The caller is responsible for the opaque anchor. It is intentionally
    // not inspected when reading a descendant, even if it is a link.
    let saved = backup_tree_with_source(
        &volume,
        &mapped,
        "trusted",
        &[PathBuf::from(r"C:\Docs")],
        1,
        &mut |_, _| {},
    )
    .unwrap();
    assert!(saved.manifest.file("docs/file.txt").is_some());
    let sets_before = list_set_ids(&volume).unwrap();

    // But if the anchor is itself the selected root it is inspected.
    let selected = PathBuf::from(r"C:\");
    let error = backup_tree_with_source(
        &volume,
        &mapped,
        "anchor",
        &[selected.clone()],
        2,
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
    assert_eq!(list_set_ids(&volume).unwrap(), sets_before);
    assert_eq!(
        fs::read(actual.join("Docs/file.txt")).unwrap(),
        b"trusted data"
    );
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn replacements_after_enumeration_stop_the_job_without_publishing_a_set() {
    use std::os::unix::fs::symlink;

    for kind in ["file-link", "ancestor-link", "file-becomes-directory"] {
        let base = tmp(kind);
        let source = base.join("source");
        let outside = base.join("outside");
        fs::create_dir_all(source.join("nested")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(source.join("a.txt"), b"first captured chunk").unwrap();
        let second = source.join("nested/z.txt");
        fs::write(&second, b"original second file").unwrap();
        fs::write(outside.join("z.txt"), b"outside sentinel").unwrap();
        let mut engine = Engine::new(volume(&base));
        let mut events = Vec::new();
        let mut changed = false;
        let error = engine
            .start_backup("race", &[source.clone()], &mut |event| {
                if matches!(&event, Event::JobProgress { phase_id, done: 1, total: 2, .. }
                if phase_id == "phase.copying_files")
                {
                    match kind {
                        "file-link" => {
                            fs::remove_file(&second).unwrap();
                            symlink(outside.join("z.txt"), &second).unwrap();
                        }
                        "ancestor-link" => {
                            fs::remove_dir_all(source.join("nested")).unwrap();
                            symlink(&outside, source.join("nested")).unwrap();
                        }
                        "file-becomes-directory" => {
                            fs::remove_file(&second).unwrap();
                            fs::create_dir(&second).unwrap();
                        }
                        _ => unreachable!(),
                    }
                    changed = true;
                }
                events.push(event);
            })
            .unwrap_err();
        assert!(changed, "injection did not run for {kind}");
        assert_eq!(error.code(), "backup.unsafe_source", "{kind}: {error:?}");
        assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &second));
        assert!(error
            .to_string()
            .contains("Chunks copied earlier may remain"));
        assert!(matches!(
            events.last(),
            Some(Event::JobFinished {
                outcome: JobOutcome::Failed,
                ..
            })
        ));
        assert!(list_set_ids(engine.volume()).unwrap().is_empty());
        assert!(engine
            .volume()
            .chunk_exists(&sha256_hex(b"first captured chunk")));
        assert!(!engine
            .volume()
            .chunk_exists(&sha256_hex(b"outside sentinel")));
        assert_eq!(
            fs::read(outside.join("z.txt")).unwrap(),
            b"outside sentinel"
        );
        let _ = fs::remove_dir_all(base);
    }
}

#[cfg(windows)]
#[test]
fn windows_junctions_are_refused_as_roots_and_reported_when_nested() {
    let base = tmp("junction");
    let source = base.join("source");
    let outside = base.join("outside");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(source.join("keep.txt"), b"inside").unwrap();
    fs::write(outside.join("secret.txt"), b"outside sentinel").unwrap();
    let junction = source.join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&outside)
        .status()
        .unwrap();
    assert!(status.success(), "could not create a test junction");
    let volume = volume(&base);
    for selected in [junction.clone(), junction.join("secret.txt")] {
        let error =
            backup_tree(&volume, "refused", &[selected.clone()], 1, &mut |_, _| {}).unwrap_err();
        assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
        assert_eq!(error.code(), "backup.unsafe_source");
        assert!(list_set_ids(&volume).unwrap().is_empty());
        assert!(volume.chunk_ids_on_disk().unwrap().is_empty());
    }
    let mut events = Vec::new();
    let mut engine = Engine::new(volume);
    let outcome = engine
        .start_backup("nested", &[source.clone()], &mut |e| events.push(e))
        .unwrap();
    assert_eq!(outcome.manifest.skipped.len(), 1);
    assert_eq!(outcome.manifest.skipped[0].path, "source/junction");
    assert!(outcome.manifest.skipped[0].reason.contains("reparse"));
    assert!(!engine
        .volume()
        .chunk_exists(&sha256_hex(b"outside sentinel")));
    assert!(
        matches!(events.last(), Some(Event::JobFinished { summary_id, .. })
        if summary_id == BACKUP_WITH_SKIPS_SUMMARY_ID)
    );

    // A regular mapped device anchor is trusted, but a junction below it
    // is still checked and reported using the caller's logical name.
    let mapped = MappedSource::new(r"C:\", source);
    let selected = PathBuf::from(r"C:\junction\secret.txt");
    let sets_before = list_set_ids(engine.volume()).unwrap();
    let error = engine
        .start_backup_with_source("mapped-refused", &[selected.clone()], &mapped, &mut |_| {})
        .unwrap_err();
    assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
    assert_eq!(list_set_ids(engine.volume()).unwrap(), sets_before);
    events.clear();
    let mapped_outcome = engine
        .start_backup_with_source("mapped", &[PathBuf::from(r"C:\")], &mapped, &mut |e| {
            events.push(e)
        })
        .unwrap();
    assert_eq!(mapped_outcome.manifest.skipped.len(), 1);
    assert_eq!(mapped_outcome.manifest.skipped[0].path, "c/junction");
    assert!(
        matches!(events.last(), Some(Event::JobFinished { summary_id, .. })
        if summary_id == BACKUP_WITH_SKIPS_SUMMARY_ID)
    );
    assert_eq!(
        fs::read(outside.join("secret.txt")).unwrap(),
        b"outside sentinel"
    );
    fs::remove_dir(junction).unwrap();
    let _ = fs::remove_dir_all(base);
}

#[cfg(windows)]
#[test]
fn windows_drive_relative_live_root_is_refused() {
    let base = tmp("drive-relative");
    let volume = volume(&base);
    let selected = PathBuf::from(r"C:relative.txt");
    let error =
        backup_tree(&volume, "refused", &[selected.clone()], 1, &mut |_, _| {}).unwrap_err();
    assert!(matches!(&error, CoreError::UnsafeBackupSource { path, .. } if path == &selected));
    assert!(error.to_string().contains("drive-relative"));
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert!(volume.chunk_ids_on_disk().unwrap().is_empty());
    let _ = fs::remove_dir_all(base);
}
