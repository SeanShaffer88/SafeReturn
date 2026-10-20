//! S1 acceptance tests for the production encrypted volume + sets.
//! Each test names the promise it pins (see docs/S1_S2_NOTES.md).

use safereturn_core::crypto::{format_recovery_key, parse_recovery_key};
use safereturn_core::*;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("safereturn-s1-{name}-{}-{n}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u32 * 31 + seed as u32) % 251) as u8)
        .collect()
}

/// Two source roots with a mix: small text, nested files, an empty file,
/// and a >1 MiB file (multiple chunks).
fn make_sources(base: &Path) -> (PathBuf, PathBuf) {
    let a = base.join("srcA");
    let b = base.join("srcB");
    fs::create_dir_all(a.join("docs/nested")).unwrap();
    fs::create_dir_all(&b).unwrap();
    fs::write(a.join("docs/important.txt"), b"tax records 2026").unwrap();
    fs::write(a.join("docs/nested/deep.bin"), pattern(300_000, 7)).unwrap();
    fs::write(a.join("empty.txt"), b"").unwrap();
    // Compressible >1 MiB: exercises multi-chunk + compression.
    fs::write(b.join("photo.raw"), vec![b'y'; 1_500_000]).unwrap();
    fs::write(b.join("readme.md"), b"# pictures\n").unwrap();
    (a, b)
}

fn open_test_volume(base: &Path) -> (UnlockedVolume, [u8; 32]) {
    let vroot = base.join("volume");
    let (locked, recovery_key) =
        Volume::create(&vroot, "correct horse battery", 1_700_000_000).unwrap();
    let unlocked = locked
        .unlock_with_passphrase("correct horse battery")
        .unwrap();
    (unlocked, recovery_key)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_recursive(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

#[test]
fn tree_backup_and_restore_roundtrip_byte_identical() {
    let base = tmp("roundtrip");
    let (a, b) = make_sources(&base);
    let (volume, _) = open_test_volume(&base);
    let mut noop = |_: u64, _: u64| {};
    let outcome = backup_tree(
        &volume,
        "first",
        &[a.clone(), b.clone()],
        1_700_000_100,
        &mut noop,
    )
    .unwrap();
    let manifest = outcome.manifest;
    assert_eq!(manifest.files.len(), 5);
    assert!(manifest.file("srca/docs/important.txt").is_some());
    assert!(manifest.file("srcb/photo.raw").is_some());
    let photo = manifest.file("srcb/photo.raw").unwrap();
    assert_eq!(photo.chunks.len(), 2, ">1 MiB file must span 2 chunks");
    assert!(manifest.files.iter().all(|f| !f.sha256.is_empty()));

    // Level-1 verify passes and reports the set's facts.
    let report = verify_set(&volume, &manifest.set_id, &mut noop).unwrap();
    assert!(report.passed(), "healthy set must verify: {report:?}");
    assert_eq!(report.files, 5);
    assert_eq!(report.chunks_checked, manifest.distinct_chunks().len());
    assert_eq!(report.plaintext_bytes, manifest.total_bytes());

    // Whole-set restore is byte-identical to the sources.
    let out = base.join("restored");
    let stats = restore_set(&volume, &manifest.set_id, &out, &HashSet::new(), &mut noop).unwrap();
    assert_eq!(stats.files_written, 5);
    assert_eq!(
        fs::read(out.join("srca/docs/important.txt")).unwrap(),
        b"tax records 2026"
    );
    assert_eq!(
        fs::read(out.join("srca/docs/nested/deep.bin")).unwrap(),
        pattern(300_000, 7)
    );
    assert_eq!(
        fs::read(out.join("srcb/photo.raw")).unwrap(),
        vec![b'y'; 1_500_000]
    );
    assert_eq!(fs::read(out.join("srca/empty.txt")).unwrap(), b"");

    // Single-file restore works too.
    let one = base.join("one.txt");
    restore_file(
        &volume,
        &manifest.set_id,
        "srca/docs/important.txt",
        &one,
        false,
    )
    .unwrap();
    assert_eq!(fs::read(&one).unwrap(), b"tax records 2026");

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn dedupe_same_content_stored_once() {
    let base = tmp("dedupe");
    let src = base.join("src");
    fs::create_dir_all(&src).unwrap();
    let blob = pattern(500_000, 3);
    fs::write(src.join("one.bin"), &blob).unwrap();
    fs::write(src.join("two.bin"), &blob).unwrap(); // same content, other name
    let (volume, _) = open_test_volume(&base);
    let mut noop = |_: u64, _: u64| {};
    let first = backup_tree(&volume, "d1", &[src.clone()], 1_700_000_200, &mut noop).unwrap();
    // Two identical 500 KB files = ONE chunk on disk.
    assert_eq!(first.chunks_written, 1);
    assert_eq!(volume.chunk_ids_on_disk().unwrap().len(), 1);

    // Backing the same tree up again as a new set writes zero new chunks.
    let second = backup_tree(&volume, "d2", &[src.clone()], 1_700_000_300, &mut noop).unwrap();
    assert_eq!(second.chunks_written, 0);
    assert_eq!(second.chunks_reused, 2);
    assert_eq!(volume.chunk_ids_on_disk().unwrap().len(), 1);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn corrupted_chunk_detected_by_verify_and_restore() {
    let base = tmp("corrupt");
    let (a, _) = make_sources(&base);
    let (volume, _) = open_test_volume(&base);
    let mut noop = |_: u64, _: u64| {};
    let outcome = backup_tree(&volume, "c", &[a], 1_700_000_400, &mut noop).unwrap();
    let manifest = outcome.manifest;
    assert!(verify_set(&volume, &manifest.set_id, &mut noop)
        .unwrap()
        .passed());

    // Flip the last byte of one chunk record (inside the AEAD tag).
    let victim = manifest.file("srca/docs/nested/deep.bin").unwrap().chunks[0].clone();
    let record_path = volume
        .root()
        .join("chunks")
        .join(&victim[..2])
        .join(&victim);
    let mut bytes = fs::read(&record_path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&record_path, &bytes).unwrap();

    // Verify names the damaged chunk.
    let report = verify_set(&volume, &manifest.set_id, &mut noop).unwrap();
    assert!(!report.passed());
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].chunk_id, victim);
    assert_eq!(report.failures[0].reason, "decrypt_failed");

    // Restore refuses too — with the chunk named, and no file written.
    let out = base.join("restored");
    let err = restore_set(&volume, &manifest.set_id, &out, &HashSet::new(), &mut noop).unwrap_err();
    assert!(
        matches!(&err, CoreError::ChunkCorrupt { chunk_id, .. } if *chunk_id == victim),
        "restore must name the corrupt chunk, got: {err:?}"
    );

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn wrong_passphrase_rejected() {
    let base = tmp("wrongpw");
    let vroot = base.join("volume");
    let (locked, _) = Volume::create(&vroot, "right passphrase", 1_700_000_500).unwrap();
    let err = locked
        .unlock_with_passphrase("wrong passphrase")
        .err()
        .expect("wrong passphrase must not unlock");
    assert!(matches!(err, CoreError::UnlockFailed), "got: {err:?}");
    // And the right one still works (no state was damaged by the failure).
    locked.unlock_with_passphrase("right passphrase").unwrap();
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn recovery_key_opens_passphrase_created_volume() {
    let base = tmp("recovery");
    let (a, _) = make_sources(&base);
    let vroot = base.join("volume");
    let (locked, recovery_key) = Volume::create(&vroot, "a passphrase", 1_700_000_600).unwrap();

    // The key file the user would save at setup time.
    let key_file = base.join("recovery-key.txt");
    fs::write(
        &key_file,
        format_recovery_key(locked.header().volume_id.as_str(), &recovery_key),
    )
    .unwrap();

    // Forget the passphrase entirely; open with the key file alone.
    let parsed = parse_recovery_key(&fs::read_to_string(&key_file).unwrap()).unwrap();
    let unlocked = locked.unlock_with_recovery_key(&parsed).unwrap();
    let mut noop = |_: u64, _: u64| {};
    let outcome = backup_tree(&unlocked, "via-key", &[a], 1_700_000_700, &mut noop).unwrap();
    assert!(verify_set(&unlocked, &outcome.manifest.set_id, &mut noop)
        .unwrap()
        .passed());

    // A well-formed key for a *different* volume fails as UnlockFailed.
    let other_key = [9u8; 32];
    assert!(matches!(
        locked.unlock_with_recovery_key(&other_key),
        Err(CoreError::UnlockFailed)
    ));
    // A garbage file fails as BadRecoveryKey, not UnlockFailed.
    assert!(matches!(
        parse_recovery_key("not a key file at all"),
        Err(CoreError::BadRecoveryKey { .. })
    ));

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn catalog_rebuilds_from_manifests_only() {
    let base = tmp("catalog");
    let (a, b) = make_sources(&base);
    let (volume, _) = open_test_volume(&base);
    let mut noop = |_: u64, _: u64| {};
    backup_tree(&volume, "one", &[a], 1_700_000_800, &mut noop).unwrap();
    backup_tree(&volume, "two", &[b], 1_700_000_900, &mut noop).unwrap();
    let expected = list_sets(&volume).unwrap();
    assert_eq!(expected.len(), 2);

    // Simulate the app and its database dying with the PC: copy ONLY the
    // volume directory elsewhere, delete the catalog there, rebuild.
    let copy_root = base.join("volume-copy");
    copy_dir_recursive(volume.root(), &copy_root);
    fs::remove_file(copy_root.join("catalog.json")).ok();
    let locked = Volume::open(&copy_root).unwrap();
    let unlocked = locked
        .unlock_with_passphrase("correct horse battery")
        .unwrap();
    let catalog = rebuild_catalog(&unlocked).unwrap();
    assert_eq!(catalog.sets, expected);
    // And the persisted catalog reads back identically.
    assert_eq!(read_catalog(&unlocked).unwrap().sets, expected);

    let _ = fs::remove_dir_all(&base);
}
