//! Capture must never silently publish a different source name.

#[cfg(unix)]
use safereturn_contract::{Event, JobOutcome};
use safereturn_core::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!(
        "safereturn-capture-names-{name}-{}-{n}",
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

#[cfg(unix)]
fn assert_unsupported_without_writes(volume: &UnlockedVolume, root: &Path) -> CoreError {
    let sets_before = list_set_ids(volume).unwrap();
    let chunks_before = volume.chunk_ids_on_disk().unwrap();
    let mut progress = Vec::new();
    let error = backup_tree(
        volume,
        "unsupported",
        &[root.to_path_buf()],
        99,
        &mut |done, total| {
            progress.push((done, total));
        },
    )
    .unwrap_err();
    assert!(
        matches!(error, CoreError::BackupPathUnsupported { .. }),
        "{error:?}"
    );
    assert_eq!(error.code(), "backup.unsupported_path");
    assert!(error.to_string().contains("No backup set was saved"));
    assert!(progress.is_empty());
    assert_eq!(list_set_ids(volume).unwrap(), sets_before);
    assert_eq!(volume.chunk_ids_on_disk().unwrap(), chunks_before);
    error
}

#[test]
fn unicode_file_and_directory_names_round_trip_for_live_and_mapped_sources() {
    let base = tmp("unicode");
    let live = base.join("live");
    let snapshot = base.join("snapshot-device");
    let filename = "Résumé-猫-�.txt";
    for tree in [&live, &snapshot] {
        fs::create_dir_all(tree.join("Docs/日本語")).unwrap();
        fs::write(
            tree.join("Docs/日本語").join(filename),
            b"original unicode data",
        )
        .unwrap();
    }
    let volume = volume(&base);
    let mapped = MappedSource::new("C:", snapshot.clone());
    let mut noop = |_: u64, _: u64| {};

    let live_set = backup_tree(&volume, "live", &[live.join("Docs")], 100, &mut noop).unwrap();
    let mapped_set = backup_tree_with_source(
        &volume,
        &mapped,
        "mapped",
        &[PathBuf::from("C:\\Docs")],
        101,
        &mut noop,
    )
    .unwrap();
    let expected = format!("docs/日本語/{filename}");
    assert_eq!(live_set.manifest.files[0].path, expected);
    assert_eq!(mapped_set.manifest.files[0].path, expected);
    assert_eq!(mapped_set.manifest.capture_mode, CaptureMode::VssSnapshot);
    assert!(!serde_json::to_string(&mapped_set.manifest)
        .unwrap()
        .contains(&snapshot.to_string_lossy().into_owned()));

    for (name, set) in [("live-out", &live_set), ("mapped-out", &mapped_set)] {
        let out = base.join(name);
        restore_set(
            &volume,
            &set.manifest.set_id,
            &out,
            &HashSet::new(),
            &mut noop,
        )
        .unwrap();
        assert_eq!(
            fs::read(out.join(&expected)).unwrap(),
            b"original unicode data"
        );
    }

    // A selected file has a slugged root label but its actual filename
    // remains exact. Mapped Windows separators work on all hosts.
    let live_file = backup_tree(
        &volume,
        "live file",
        &[live.join("Docs/日本語").join(filename)],
        102,
        &mut noop,
    )
    .unwrap();
    let mapped_file = backup_tree_with_source(
        &volume,
        &mapped,
        "mapped file",
        &[PathBuf::from(format!("C:\\Docs\\日本語\\{filename}"))],
        103,
        &mut noop,
    )
    .unwrap();
    assert_eq!(live_file.manifest.roots, mapped_file.manifest.roots);
    assert_eq!(
        live_file.manifest.files[0].path,
        mapped_file.manifest.files[0].path
    );
    assert_eq!(
        live_file.manifest.files[0].path,
        format!("{}/{filename}", live_file.manifest.roots[0])
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn mapped_windows_components_cannot_change_the_device_prefix() {
    let base = tmp("mapped-prefix");
    let snapshot = base.join("snapshot");
    fs::create_dir_all(&snapshot).unwrap();
    let mapped = MappedSource::new("C:", snapshot.clone());
    for root in [
        r"C:\folder\D:escape",
        r"C:\folder\file:stream",
        r"C:\folder\NUL.txt",
        "C:\\folder\\trailing. ",
    ] {
        let err = mapped.resolve_root(Path::new(root)).unwrap_err();
        assert!(
            matches!(err, CoreError::BackupPathUnsupported { .. }),
            "{root}: {err:?}"
        );
    }
    assert_eq!(
        mapped
            .resolve_root(Path::new(r"C:\folder\résumé.txt"))
            .unwrap(),
        snapshot.join("folder").join("résumé.txt")
    );
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn native_backslashes_non_unicode_and_unportable_names_refuse_before_any_chunk() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;

    let base = tmp("native");
    let volume = volume(&base);
    let existing = base.join("existing");
    fs::create_dir_all(&existing).unwrap();
    fs::write(existing.join("old.txt"), b"existing backup").unwrap();
    let old = backup_tree(&volume, "existing", &[existing], 1, &mut |_, _| {})
        .unwrap()
        .manifest;
    let old_manifest = fs::read(
        volume
            .root()
            .join("sets")
            .join(format!("{}.json", old.set_id)),
    )
    .unwrap();

    let child = base.join("child");
    fs::create_dir_all(&child).unwrap();
    let child_bad = child.join("looks\\like-a-folder.txt");
    fs::write(&child_bad, b"child sentinel").unwrap();
    let err = assert_unsupported_without_writes(&volume, &child);
    assert!(matches!(err, CoreError::BackupPathUnsupported { ref path, .. } if path == &child_bad));
    assert_eq!(fs::read(&child_bad).unwrap(), b"child sentinel");

    let file_root = base.join("picked\\file.txt");
    fs::write(&file_root, b"root sentinel").unwrap();
    let err = assert_unsupported_without_writes(&volume, &file_root);
    assert!(matches!(err, CoreError::BackupPathUnsupported { ref path, .. } if path == &file_root));
    assert_eq!(fs::read(&file_root).unwrap(), b"root sentinel");

    let dir_source = base.join("directory");
    let bad_dir = dir_source.join("empty\\directory");
    fs::create_dir_all(&bad_dir).unwrap();
    assert_unsupported_without_writes(&volume, &dir_source);
    assert!(bad_dir.is_dir());

    let link_source = base.join("links");
    fs::create_dir_all(&link_source).unwrap();
    symlink("missing", link_source.join("skipped\\link")).unwrap();
    assert_unsupported_without_writes(&volume, &link_source);

    let bytes_source = base.join("bytes");
    fs::create_dir_all(&bytes_source).unwrap();
    let bad_name = OsString::from_vec(b"bad-\xff.txt".to_vec());
    let bad_file = bytes_source.join(&bad_name);
    fs::write(&bad_file, b"raw bytes sentinel").unwrap();
    // A valid filename containing U+FFFD must not be confused with the
    // invalid bytes that a lossy conversion would replace with it.
    fs::write(bytes_source.join("bad-�.txt"), b"different file").unwrap();
    let err = assert_unsupported_without_writes(&volume, &bytes_source);
    assert!(matches!(err, CoreError::BackupPathUnsupported { ref path, .. } if path == &bad_file));
    assert!(err.to_string().contains("not valid Unicode"));
    assert_eq!(fs::read(&bad_file).unwrap(), b"raw bytes sentinel");
    assert_eq!(
        fs::read(bytes_source.join("bad-�.txt")).unwrap(),
        b"different file"
    );
    assert_unsupported_without_writes(&volume, &bad_file);

    let bad_parent = base.join(OsString::from_vec(b"parent-\xfe".to_vec()));
    fs::create_dir_all(&bad_parent).unwrap();
    fs::write(bad_parent.join("valid.txt"), b"another sentinel").unwrap();
    assert_unsupported_without_writes(&volume, &bad_parent.join("valid.txt"));

    // A safe first root does not get copied when a later root is invalid.
    let safe = base.join("safe");
    fs::create_dir_all(&safe).unwrap();
    fs::write(safe.join("new.txt"), b"new chunk must not be written").unwrap();
    let before = volume.chunk_ids_on_disk().unwrap();
    let mut events = Vec::new();
    let mut engine = Engine::new(volume);
    let error = engine
        .start_backup("mixed", &[safe, child], &mut |event| events.push(event))
        .unwrap_err();
    assert_eq!(error.code(), "backup.unsupported_path");
    assert!(matches!(events.first(), Some(Event::JobStarted { .. })));
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            ..
        })
    ));
    assert!(!events
        .iter()
        .any(|event| matches!(event, Event::JobProgress { .. })));
    assert_eq!(engine.volume().chunk_ids_on_disk().unwrap(), before);
    assert_eq!(
        list_set_ids(engine.volume()).unwrap(),
        vec![old.set_id.clone()]
    );
    assert_eq!(
        fs::read(
            engine
                .volume()
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
fn mapped_source_rejects_invalid_logical_names_but_keeps_device_prefix_opaque() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let base = tmp("mapped-raw");
    // A snapshot/device prefix is not written into the manifest, so it
    // need not itself be Unicode.
    let snapshot = base.join(OsString::from_vec(b"snapshot-\xff".to_vec()));
    fs::create_dir_all(snapshot.join("Docs")).unwrap();
    fs::write(snapshot.join("Docs/valid.txt"), b"valid").unwrap();
    fs::write(snapshot.join("Docs/lost-�.txt"), b"not the requested bytes").unwrap();
    let volume = volume(&base);
    let mapped = MappedSource::new("C:", snapshot.clone());
    let bad_root = PathBuf::from(OsString::from_vec(b"C:\\Docs\\lost-\xff.txt".to_vec()));
    assert!(matches!(
        mapped.resolve_root(&bad_root),
        Err(CoreError::BackupPathUnsupported { .. })
    ));
    let before = volume.chunk_ids_on_disk().unwrap();
    let err = backup_tree_with_source(&volume, &mapped, "bad", &[bad_root], 1, &mut |_, _| {})
        .unwrap_err();
    assert_eq!(err.code(), "backup.unsupported_path");
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert_eq!(volume.chunk_ids_on_disk().unwrap(), before);
    assert_eq!(
        fs::read(snapshot.join("Docs/lost-�.txt")).unwrap(),
        b"not the requested bytes"
    );

    let bad_child = snapshot
        .join("Docs")
        .join(OsString::from_vec(b"child-\xfe".to_vec()));
    fs::write(&bad_child, b"raw child").unwrap();
    let err = backup_tree_with_source(
        &volume,
        &mapped,
        "bad child",
        &[PathBuf::from(r"C:\Docs")],
        2,
        &mut |_, _| {},
    )
    .unwrap_err();
    assert!(matches!(&err, CoreError::BackupPathUnsupported { path, .. }
        if path == &PathBuf::from(r"C:\Docs").join(bad_child.file_name().unwrap())));
    assert!(
        !format!("{err:?}").contains("snapshot-"),
        "diagnostics should use logical roots"
    );
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert_eq!(volume.chunk_ids_on_disk().unwrap(), before);

    fs::remove_file(bad_child).unwrap();
    let good = backup_tree_with_source(
        &volume,
        &mapped,
        "good",
        &[PathBuf::from(r"C:\Docs")],
        3,
        &mut |_, _| {},
    )
    .unwrap();
    assert!(good.manifest.file("docs/valid.txt").is_some());
    assert!(good.manifest.file("docs/lost-�.txt").is_some());
    let _ = fs::remove_dir_all(base);
}

#[cfg(target_os = "linux")]
#[test]
fn file_and_directory_case_aliases_are_rejected_before_copying() {
    let base = tmp("case");
    let volume = volume(&base);
    let files = base.join("files");
    fs::create_dir_all(&files).unwrap();
    fs::write(files.join("Report.txt"), b"first").unwrap();
    fs::write(files.join("report.txt"), b"second").unwrap();
    let err = assert_unsupported_without_writes(&volume, &files);
    assert!(err.to_string().contains("conflicts"));

    let dirs = base.join("dirs");
    fs::create_dir_all(dirs.join("Reports")).unwrap();
    fs::create_dir_all(dirs.join("reports")).unwrap();
    fs::write(dirs.join("Reports/a.txt"), b"first").unwrap();
    fs::write(dirs.join("reports/b.txt"), b"second").unwrap();
    let err = assert_unsupported_without_writes(&volume, &dirs);
    assert!(err.to_string().contains("aliases"));
    assert_eq!(fs::read(dirs.join("Reports/a.txt")).unwrap(), b"first");
    assert_eq!(fs::read(dirs.join("reports/b.txt")).unwrap(), b"second");
    let _ = fs::remove_dir_all(base);
}

#[cfg(unix)]
#[test]
fn native_directory_root_uses_its_whole_component_for_the_display_slug() {
    let base = tmp("root-slug");
    let source = base.join("special\\root");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file.txt"), b"original").unwrap();
    let volume = volume(&base);
    let outcome = backup_tree(&volume, "directory", &[source], 1, &mut |_, _| {}).unwrap();
    assert_eq!(outcome.manifest.roots, ["special-root"]);
    assert_eq!(outcome.manifest.files[0].path, "special-root/file.txt");
    let _ = fs::remove_dir_all(base);
}

#[cfg(windows)]
#[test]
fn unpaired_surrogate_logical_root_is_refused_before_mapping_or_copying() {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    let base = tmp("windows-unpaired");
    let volume = volume(&base);
    let mapped = MappedSource::new("C:", base.join("snapshot"));
    let mut wide: Vec<u16> = "C:\\Docs\\bad-".encode_utf16().collect();
    wide.push(0xd800);
    wide.extend(".txt".encode_utf16());
    let root = PathBuf::from(OsString::from_wide(&wide));
    assert!(matches!(
        mapped.resolve_root(&root),
        Err(CoreError::BackupPathUnsupported { .. })
    ));
    for source in [
        &LiveSource as &dyn CaptureSource,
        &mapped as &dyn CaptureSource,
    ] {
        let err =
            backup_tree_with_source(&volume, source, "bad", &[root.clone()], 1, &mut |_, _| {})
                .unwrap_err();
        assert_eq!(err.code(), "backup.unsupported_path");
    }
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert!(volume.chunk_ids_on_disk().unwrap().is_empty());
    let _ = fs::remove_dir_all(base);
}
