//! Backup completion and Quick Check must not claim success for data
//! that cannot be reconstructed from the backup volume.

use safereturn_contract::{Event, JobOutcome};
use safereturn_core::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn tmp(name: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "safereturn-integrity-{name}-{}-{n}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn volume(base: &Path) -> UnlockedVolume {
    let (locked, recovery) = Volume::create(base.join("volume"), "test password", 42).unwrap();
    locked.unlock_with_recovery_key(&recovery).unwrap()
}

fn chunk_path(volume: &UnlockedVolume, id: &str) -> PathBuf {
    volume.root().join("chunks").join(&id[..2]).join(id)
}

fn damage_chunk(path: &Path) -> Vec<u8> {
    let mut bytes = fs::read(path).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    fs::write(path, &bytes).unwrap();
    bytes
}

fn save_manifest(volume: &UnlockedVolume, manifest: &SetManifest) {
    let path = volume
        .root()
        .join("sets")
        .join(format!("{}.json", manifest.set_id));
    fs::write(path, serde_json::to_vec_pretty(manifest).unwrap()).unwrap();
}

#[test]
fn corrupt_deduplicated_chunk_cannot_become_a_successful_backup() {
    let base = tmp("dedupe-corrupt");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("important.txt"), b"important original data").unwrap();
    let mut engine = Engine::new(volume(&base));
    let mut events = Vec::new();
    let first = engine
        .start_backup("first", &[source.clone()], &mut |e| events.push(e))
        .unwrap();
    assert!(events.iter().any(|event| matches!(event,
        Event::JobProgress { phase_id, done: 1, total: 1, unit, .. }
            if phase_id == "phase.checking_backup" && unit == "chunk references"
    )));
    let id = first.manifest.files[0].chunks[0].clone();
    let path = chunk_path(engine.volume(), &id);
    let damaged = damage_chunk(&path);
    let old_ids = list_set_ids(engine.volume()).unwrap();

    events.clear();
    let err = engine
        .start_backup("second", &[source.clone()], &mut |e| events.push(e))
        .unwrap_err();
    assert!(matches!(err, CoreError::BackupVerificationFailed { .. }));
    assert_eq!(err.code(), "backup.verification_failed");
    let message = err.to_string();
    assert!(message.contains(&id), "{message}");
    assert!(message.contains("decrypt_failed"), "{message}");
    assert!(message.contains("source/important.txt"), "{message}");
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            ..
        })
    ));
    assert!(!events.iter().any(|event| matches!(
        event,
        Event::JobFinished {
            outcome: JobOutcome::Succeeded,
            ..
        }
    )));
    assert_eq!(list_set_ids(engine.volume()).unwrap(), old_ids);
    assert_eq!(fs::read(&path).unwrap(), damaged, "no silent repair");
    assert_eq!(
        fs::read(source.join("important.txt")).unwrap(),
        b"important original data"
    );
    let _ = fs::remove_dir_all(base);
}

#[test]
fn new_chunk_is_read_back_before_the_manifest_is_published() {
    let base = tmp("new-chunk");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    let original = b"bytes to verify after writing";
    fs::write(source.join("file.txt"), original).unwrap();
    let volume = volume(&base);
    let id = sha256_hex(original);
    let path = chunk_path(&volume, &id);
    let mut injected = false;

    let error = backup_tree(
        &volume,
        "fresh",
        &[source.clone()],
        50,
        &mut |done, total| {
            if done == total && !injected {
                damage_chunk(&path);
                injected = true;
            }
        },
    )
    .unwrap_err();
    assert!(injected);
    assert!(matches!(error, CoreError::BackupVerificationFailed { .. }));
    assert!(error.to_string().contains(&id));
    assert!(list_set_ids(&volume).unwrap().is_empty());
    assert_eq!(fs::read(source.join("file.txt")).unwrap(), original);
    assert!(path.exists(), "previously written pool chunks remain");
    let _ = fs::remove_dir_all(base);
}

#[test]
fn quick_check_detects_inconsistent_file_assembly_and_duplicate_paths() {
    let base = tmp("assembly");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    let mut data = vec![b'a'; SET_CHUNK_SIZE];
    data.extend(vec![b'b'; SET_CHUNK_SIZE]);
    fs::write(source.join("large.bin"), data).unwrap();
    fs::write(source.join("empty.txt"), b"").unwrap();
    let volume = volume(&base);
    let original = backup_tree(&volume, "check", &[source], 60, &mut |_, _| {})
        .unwrap()
        .manifest;
    let big = original
        .files
        .iter()
        .position(|f| f.path.ends_with("large.bin"))
        .unwrap();
    let empty = original
        .files
        .iter()
        .position(|f| f.path.ends_with("empty.txt"))
        .unwrap();
    assert_eq!(original.files[big].chunks.len(), 2);

    for case in [
        "wrong_hash",
        "wrong_size",
        "reordered",
        "no_chunks",
        "empty_hash",
        "duplicate",
    ] {
        let mut altered = original.clone();
        match case {
            "wrong_hash" => altered.files[big].sha256 = "0".repeat(64),
            "wrong_size" => altered.files[big].size += 1,
            "reordered" => altered.files[big].chunks.reverse(),
            "no_chunks" => altered.files[big].chunks.clear(),
            "empty_hash" => altered.files[empty].sha256 = "0".repeat(64),
            "duplicate" => altered.files.push(altered.files[big].clone()),
            _ => unreachable!(),
        }
        save_manifest(&volume, &altered);
        let report = verify_set(&volume, &original.set_id, &mut |_, _| {}).unwrap();
        assert!(!report.passed(), "{case} incorrectly passed");
        assert!(report.failures.is_empty(), "chunks remain intact: {case}");
        let (path, reason) = match case {
            "wrong_hash" | "reordered" => (&original.files[big].path, "hash_mismatch"),
            "wrong_size" | "no_chunks" => (&original.files[big].path, "size_mismatch"),
            "empty_hash" => (&original.files[empty].path, "hash_mismatch"),
            "duplicate" => (&original.files[big].path, "duplicate_path"),
            _ => unreachable!(),
        };
        assert!(
            report
                .file_failures
                .iter()
                .any(|f| f.path == *path && f.reason == reason),
            "{case}: {:?}",
            report.file_failures
        );
    }
    save_manifest(&volume, &original);
    assert!(verify_set(&volume, &original.set_id, &mut |_, _| {})
        .unwrap()
        .passed());
    let _ = fs::remove_dir_all(base);
}

#[test]
fn invalid_chunk_ids_are_failures_not_panics_or_paths() {
    let base = tmp("bad-id");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file"), b"data").unwrap();
    let volume = volume(&base);
    let original = backup_tree(&volume, "check", &[source], 70, &mut |_, _| {})
        .unwrap()
        .manifest;

    for invalid in [
        "",
        "a",
        "💥",
        "../outside",
        &"A".repeat(64),
        &"g".repeat(64),
    ] {
        let mut altered = original.clone();
        altered.files[0].chunks[0] = invalid.to_string();
        save_manifest(&volume, &altered);
        let report = verify_set(&volume, &original.set_id, &mut |_, _| {}).unwrap();
        assert!(!report.passed());
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].chunk_id, invalid);
        assert_eq!(report.failures[0].reason, "bad_record");
        assert_eq!(report.file_failures[0].reason, "chunk_unavailable");
        assert!(!volume.chunk_exists(invalid));
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn bad_manifest_version_identity_and_overflow_fail_the_job() {
    let base = tmp("manifest");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("a"), b"a").unwrap();
    fs::write(source.join("b"), b"b").unwrap();
    let mut engine = Engine::new(volume(&base));
    let original = engine
        .start_backup("check", &[source], &mut |_| {})
        .unwrap()
        .manifest;
    let manifest_path = engine
        .volume()
        .root()
        .join("sets")
        .join(format!("{}.json", original.set_id));

    for case in ["version", "identity", "overflow"] {
        let mut altered = original.clone();
        match case {
            "version" => altered.format_version += 1,
            // Write it under the original filename to simulate drift.
            "identity" => altered.set_id = "different-set".to_string(),
            "overflow" => altered.files[0].size = u64::MAX,
            _ => unreachable!(),
        }
        fs::write(&manifest_path, serde_json::to_vec_pretty(&altered).unwrap()).unwrap();
        let mut events = Vec::new();
        let err = engine
            .start_verify(&original.set_id, &mut |e| events.push(e))
            .unwrap_err();
        assert!(
            matches!(err, CoreError::InvalidSetManifest { .. }),
            "{case}: {err:?}"
        );
        assert!(matches!(
            events.last(),
            Some(Event::JobFinished {
                outcome: JobOutcome::Failed,
                ..
            })
        ));
        assert_eq!(
            fs::read(&manifest_path).unwrap(),
            serde_json::to_vec_pretty(&altered).unwrap(),
            "checking must not alter the manifest"
        );
    }
    let _ = fs::remove_dir_all(base);
}

#[test]
fn deduplicated_references_and_empty_files_are_checked_honestly() {
    let base = tmp("duplicates");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("a"), b"same bytes").unwrap();
    fs::write(source.join("b"), b"same bytes").unwrap();
    fs::write(source.join("empty"), b"").unwrap();
    let volume = volume(&base);
    let outcome = backup_tree(&volume, "dedupe", &[source], 80, &mut |_, _| {}).unwrap();
    assert_eq!(outcome.chunks_written, 1);
    assert_eq!(outcome.chunks_reused, 1);
    let mut progress = Vec::new();
    let report = verify_set(&volume, &outcome.manifest.set_id, &mut |done, total| {
        progress.push((done, total))
    })
    .unwrap();
    assert!(report.passed());
    assert_eq!(report.files, 3);
    assert_eq!(report.chunks_checked, 1);
    assert_eq!(progress, vec![(1, 2), (2, 2)]);

    // One missing shared chunk is counted once and both affected files
    // are named; the unrelated empty file remains valid.
    let id = outcome.manifest.files[0].chunks[0].clone();
    fs::remove_file(chunk_path(&volume, &id)).unwrap();
    progress.clear();
    let report = verify_set(&volume, &outcome.manifest.set_id, &mut |done, total| {
        progress.push((done, total))
    })
    .unwrap();
    assert!(!report.passed());
    assert_eq!(report.chunks_checked, 1);
    assert_eq!(report.chunks_ok, 0);
    assert_eq!(report.failures[0].reason, "missing");
    assert_eq!(report.file_failures.len(), 2);
    assert!(report
        .file_failures
        .iter()
        .all(|f| f.reason == "chunk_unavailable"));
    assert_eq!(progress, vec![(1, 2), (2, 2)]);
    let _ = fs::remove_dir_all(base);
}

#[test]
fn corrupted_chunk_length_header_does_not_cause_huge_allocation() {
    let base = tmp("bad-length");
    let volume = volume(&base);
    let id = volume.put_chunk(&vec![b'x'; SET_CHUNK_SIZE]).unwrap();
    let path = chunk_path(&volume, &id);
    let mut record = fs::read(&path).unwrap();
    assert_eq!(record[5], 2, "test needs a compressed chunk");
    record[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(&path, record).unwrap();
    let err = volume.get_chunk(&id).unwrap_err();
    assert!(matches!(
        err,
        CoreError::ChunkCorrupt {
            reason: ChunkCorruptReason::HashMismatch | ChunkCorruptReason::BadRecord,
            ..
        }
    ));
    let _ = fs::remove_dir_all(base);
}

#[test]
fn manifest_write_failure_is_reported_without_claiming_nothing_was_written() {
    let base = tmp("write-failed");
    let source = base.join("source");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("file"), b"some content").unwrap();
    let volume = volume(&base);
    // A file in place of the sets directory simulates a destination
    // that cannot accept a manifest, after the chunk has been stored.
    let sets = volume.root().join("sets");
    fs::remove_dir(&sets).unwrap();
    fs::write(&sets, b"do not overwrite").unwrap();
    let mut engine = Engine::new(volume);
    let mut events = Vec::new();
    let err = engine
        .start_backup("cannot-publish", &[source.clone()], &mut |e| events.push(e))
        .unwrap_err();
    assert!(
        matches!(err, CoreError::BackupWriteFailed { .. }),
        "{err:?}"
    );
    assert_eq!(err.code(), "backup.write_failed");
    assert!(matches!(
        events.last(),
        Some(Event::JobFinished {
            outcome: JobOutcome::Failed,
            ..
        })
    ));
    assert_eq!(fs::read(&sets).unwrap(), b"do not overwrite");
    assert_eq!(fs::read(source.join("file")).unwrap(), b"some content");
    assert_eq!(engine.volume().chunk_ids_on_disk().unwrap().len(), 1);
    let _ = fs::remove_dir_all(base);
}
