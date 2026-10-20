use safereturn_core::*;
use std::fs;
use std::path::PathBuf;

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("safereturn-proto-{}-{}", name, std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn backup_verify_and_file_restore_roundtrip() {
    let base = tmp("roundtrip");
    let src = base.join("src");
    fs::create_dir_all(src.join("docs")).unwrap();
    fs::write(src.join("docs/important.txt"), b"tax records 2026").unwrap();
    // A file larger than one chunk, to exercise chunk ordering.
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("big.bin"), &big).unwrap();
    fs::write(src.join("empty.txt"), b"").unwrap();

    let store = ChunkStore::open(base.join("store")).unwrap();
    let manifest = store.backup_dir("test-1", &src).unwrap();
    assert_eq!(manifest.files.len(), 3);

    // Level-1 rehearsal passes on a healthy backup.
    let report = store.verify(&manifest);
    assert!(report.passed(), "healthy backup must verify: {report:?}");
    assert!(report.chunks_checked >= 5);

    // File-level restore returns byte-identical content.
    let out = base.join("restored/important.txt");
    store
        .restore_file(&manifest, "docs/important.txt", &out)
        .unwrap();
    assert_eq!(fs::read(&out).unwrap(), b"tax records 2026");

    let out_big = base.join("restored/big.bin");
    store.restore_file(&manifest, "big.bin", &out_big).unwrap();
    assert_eq!(fs::read(&out_big).unwrap(), big);

    let _ = fs::remove_dir_all(&base);
}

#[test]
fn verify_detects_corruption_honestly() {
    let base = tmp("corrupt");
    let src = base.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), vec![b'x'; 10_000]).unwrap();

    let store_root = base.join("store");
    let store = ChunkStore::open(&store_root).unwrap();
    let manifest = store.backup_dir("test-2", &src).unwrap();
    assert!(store.verify(&manifest).passed());

    // Corrupt the single chunk on disk, as bit-rot / a failing drive would.
    let hash = manifest.files[0].chunks[0].clone();
    let chunk_file = store_root.join("chunks").join(&hash[..2]).join(&hash);
    fs::write(&chunk_file, b"corrupted-bytes").unwrap();

    let report = store.verify(&manifest);
    assert!(
        !report.passed(),
        "corrupt backup must NOT pass verification"
    );
    assert_eq!(report.corrupt, vec![hash]);

    let _ = fs::remove_dir_all(&base);
}
