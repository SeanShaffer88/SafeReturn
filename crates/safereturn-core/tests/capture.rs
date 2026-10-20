//! S3 acceptance tests for capture sources (see docs/S3_NOTES.md).
//! The promise pinned here: a backup read through a prefix-mapped
//! source produces the same set as a live backup of the same content —
//! same logical paths, same hashes, same chunks — with the capture mode
//! recorded honestly and no mapped (snapshot device) path anywhere in
//! the manifest.

use safereturn_core::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("safereturn-s3-{name}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32 * 31 + seed as u32) % 251) as u8)
        .collect()
}

/// One content tree: Docs (nested) + Pics, written under `root`.
fn make_content(root: &Path) {
    fs::create_dir_all(root.join("Docs/nested")).unwrap();
    fs::create_dir_all(root.join("Pics")).unwrap();
    fs::write(root.join("Docs/important.txt"), b"tax records 2026").unwrap();
    fs::write(root.join("Docs/nested/deep.bin"), pattern(300_000, 7)).unwrap();
    fs::write(root.join("Pics/photo.raw"), vec![b'y'; 1_500_000]).unwrap();
}

fn open_test_volume(base: &Path, name: &str) -> UnlockedVolume {
    let vroot = base.join(name);
    let (locked, _) = Volume::create(&vroot, "correct horse battery", 1_700_000_000).unwrap();
    locked
        .unlock_with_passphrase("correct horse battery")
        .unwrap()
}

/// The comparable part of a manifest's file list (mtimes legitimately
/// differ between two physical copies of the same content).
fn file_facts(m: &SetManifest) -> Vec<(String, u64, String, Vec<String>)> {
    m.files
        .iter()
        .map(|f| (f.path.clone(), f.size, f.sha256.clone(), f.chunks.clone()))
        .collect()
}

#[test]
fn mapped_source_matches_live_and_records_logical_paths_only() {
    let base = tmp("mapped");
    // "Live" content and the identical content under a stand-in
    // snapshot root (in production: the snapshot device object).
    let live_root = base.join("live");
    let snap_root = base.join("snap-device");
    make_content(&live_root);
    make_content(&snap_root);

    let live_volume = open_test_volume(&base, "vol-live");
    let snap_volume = open_test_volume(&base, "vol-snap");
    let mut noop = |_: u64, _: u64| {};

    let live = backup_tree(
        &live_volume,
        "same",
        &[live_root.join("Docs"), live_root.join("Pics")],
        1_700_001_000,
        &mut noop,
    )
    .unwrap();
    assert_eq!(live.manifest.capture_mode, CaptureMode::Live);

    let mapped = MappedSource::new("C:", snap_root.clone());
    let snap = backup_tree_with_source(
        &snap_volume,
        &mapped,
        "same",
        &[PathBuf::from("C:\\Docs"), PathBuf::from("C:\\Pics")],
        1_700_001_000,
        &mut noop,
    )
    .unwrap();

    // Same set, honestly labelled: identical file facts and root names,
    // capture mode is the only difference.
    assert_eq!(snap.manifest.capture_mode, CaptureMode::VssSnapshot);
    assert_eq!(snap.manifest.roots, live.manifest.roots);
    assert_eq!(file_facts(&snap.manifest), file_facts(&live.manifest));
    assert!(snap.manifest.file("docs/important.txt").is_some());
    assert!(snap.manifest.file("pics/photo.raw").is_some());

    // No mapped path leaks into the manifest: the device root string
    // must not appear anywhere in its JSON.
    let json = serde_json::to_string_pretty(&snap.manifest).unwrap();
    assert!(
        !json.contains(&snap_root.to_string_lossy().into_owned()),
        "snapshot device root leaked into manifest:\n{json}"
    );
    assert!(json.contains("\"vss_snapshot\""));

    // And the snapshot set restores byte-identically.
    let out = base.join("restored");
    let stats = restore_set(
        &snap_volume,
        &snap.manifest.set_id,
        &out,
        &std::collections::HashSet::new(),
        &mut noop,
    )
    .unwrap();
    assert_eq!(stats.files_written, 3);
    assert_eq!(
        fs::read(out.join("docs/important.txt")).unwrap(),
        b"tax records 2026"
    );
    assert_eq!(
        fs::read(out.join("pics/photo.raw")).unwrap(),
        vec![b'y'; 1_500_000]
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn mapped_source_file_root_matches_live() {
    let base = tmp("mapped-file");
    let live_root = base.join("live");
    let snap_root = base.join("snap-device");
    make_content(&live_root);
    make_content(&snap_root);
    let live_volume = open_test_volume(&base, "vol-live");
    let snap_volume = open_test_volume(&base, "vol-snap");
    let mut noop = |_: u64, _: u64| {};

    let live = backup_tree(
        &live_volume,
        "one",
        &[live_root.join("Docs/important.txt")],
        1_700_002_000,
        &mut noop,
    )
    .unwrap();
    let mapped = MappedSource::new("C:", snap_root);
    let snap = backup_tree_with_source(
        &snap_volume,
        &mapped,
        "one",
        &[PathBuf::from("C:\\Docs\\important.txt")],
        1_700_002_000,
        &mut noop,
    )
    .unwrap();
    assert_eq!(file_facts(&snap.manifest), file_facts(&live.manifest));
    assert_eq!(snap.manifest.files[0].path, "important-txt/important.txt");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn mapped_source_rejects_roots_outside_the_volume() {
    let base = tmp("mapped-reject");
    let snap_root = base.join("snap-device");
    make_content(&snap_root);
    let volume = open_test_volume(&base, "vol");
    let mapped = MappedSource::new("C:", snap_root);
    let mut noop = |_: u64, _: u64| {};

    // A root on another volume cannot come from this snapshot.
    let err = backup_tree_with_source(
        &volume,
        &mapped,
        "nope",
        &[PathBuf::from("D:\\Elsewhere")],
        1_700_003_000,
        &mut noop,
    )
    .unwrap_err();
    assert!(
        matches!(err, CoreError::CaptureRootOutsideVolume { .. }),
        "got: {err:?}"
    );
    assert_eq!(err.code(), "backup.capture_root_outside_volume");

    // A root that escapes via ".." is rejected too.
    let err = backup_tree_with_source(
        &volume,
        &mapped,
        "nope",
        &[PathBuf::from("C:\\..\\escape")],
        1_700_003_000,
        &mut noop,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::CaptureRootOutsideVolume { .. }));

    // A volume-prefixed lookalike ("C:Docs" is a drive-relative path on
    // Windows, not C:\Docs) is not silently reinterpreted.
    let err = backup_tree_with_source(
        &volume,
        &mapped,
        "nope",
        &[PathBuf::from("C:Docs")],
        1_700_003_000,
        &mut noop,
    )
    .unwrap_err();
    assert!(matches!(err, CoreError::CaptureRootOutsideVolume { .. }));

    // Nothing was saved by any of the refused attempts.
    assert!(list_set_ids(&volume).unwrap().is_empty());

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn pre_s3_manifests_read_as_live_captures() {
    let base = tmp("legacy-manifest");
    let src = base.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    let volume = open_test_volume(&base, "vol");
    let mut noop = |_: u64, _: u64| {};
    let outcome = backup_tree(&volume, "legacy", &[src], 1_700_004_000, &mut noop).unwrap();
    assert_eq!(outcome.manifest.capture_mode, CaptureMode::Live);

    // Simulate a manifest written before capture_mode existed: same
    // set, field removed, stored under a new set id.
    let mut value = serde_json::to_value(&outcome.manifest).unwrap();
    value.as_object_mut().unwrap().remove("capture_mode");
    value["set_id"] = serde_json::Value::String("legacy-set".to_string());
    let path = volume.root().join("sets").join("legacy-set.json");
    fs::write(&path, serde_json::to_string_pretty(&value).unwrap()).unwrap();

    let read = read_set_manifest(&volume, "legacy-set").unwrap();
    assert_eq!(read.capture_mode, CaptureMode::Live);
    assert_eq!(read.files.len(), 1);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn mapped_source_resolves_volume_root_and_forward_slashes() {
    let base = tmp("mapped-resolve");
    let snap_root = base.join("dev");
    fs::create_dir_all(snap_root.join("a/b")).unwrap();
    let mapped = MappedSource::new("C:", snap_root.clone());
    assert_eq!(mapped.resolve_root(Path::new("C:\\")).unwrap(), snap_root);
    assert_eq!(mapped.resolve_root(Path::new("C:")).unwrap(), snap_root);
    assert_eq!(
        mapped.resolve_root(Path::new("C:/a/b")).unwrap(),
        snap_root.join("a").join("b")
    );
    assert_eq!(
        mapped.resolve_root(Path::new("c:\\a")).unwrap(),
        snap_root.join("a")
    );
    let _ = fs::remove_dir_all(&base);
}
