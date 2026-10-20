//! Backup sets: the unit a user thinks in ("Tuesday's backup of Documents
//! and Pictures"). A set = one manifest JSON stored on the volume at
//! `sets/<set_id>.json`, listing every file with its size, modification
//! time, whole-file SHA-256, and the ordered chunk ids that make it up.
//!
//! Set manifests are the source of truth. `catalog.json` is only an index
//! over them and can always be rebuilt by scanning `sets/` — that rebuild
//! is implemented and tested, because "the catalog can be rebuilt from
//! the backup drive alone" is a promise the Recovery Rehearsal makes.

use crate::capture::{last_path_segment, CaptureMode, CaptureSource, LiveSource};
use crate::crypto::random_array;
use crate::error::{io_at, CoreError, Result};
use crate::hex;
use crate::volume::{sha256_hex, UnlockedVolume};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const SET_FORMAT_VERSION: u32 = 1;
/// Production chunk size: 1 MiB of plaintext per chunk (plan §4: fixed-size
/// is acceptable for Phase 1; content-defined chunking is Phase 2).
pub const SET_CHUNK_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetFileEntry {
    /// Path inside the set: "<root display name>/<relative path>", '/'
    /// separators on every platform.
    pub path: String,
    pub size: u64,
    pub mtime_unix: u64,
    /// SHA-256 of the whole file's content.
    pub sha256: String,
    /// Ordered chunk ids; concatenating their plaintext rebuilds the file.
    pub chunks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedEntry {
    pub path: String,
    /// Why it was not backed up, plain language (e.g. "symbolic link —
    /// links are not followed"). Shown to the user; never silent.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetManifest {
    pub format_version: u32,
    pub set_id: String,
    pub label: String,
    pub created_unix: u64,
    /// Display names of the source roots, in the order given. File paths
    /// in this manifest are prefixed with these names.
    pub roots: Vec<String>,
    /// How this set was captured (S3): read from the live filesystem, or
    /// from a VSS snapshot. Absent in pre-S3 manifests — serde's default
    /// (Live) is the truthful value for all of them.
    #[serde(default)]
    pub capture_mode: CaptureMode,
    pub files: Vec<SetFileEntry>,
    pub skipped: Vec<SkippedEntry>,
}

impl SetManifest {
    pub fn total_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn distinct_chunks(&self) -> BTreeSet<&str> {
        self.files
            .iter()
            .flat_map(|f| f.chunks.iter().map(|c| c.as_str()))
            .collect()
    }

    pub fn file(&self, path: &str) -> Option<&SetFileEntry> {
        self.files.iter().find(|f| f.path == path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSet {
    pub set_id: String,
    pub label: String,
    pub created_unix: u64,
    pub files: u64,
    pub bytes: u64,
    pub distinct_chunks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub format_version: u32,
    pub sets: Vec<CatalogSet>,
}

pub fn summarize(manifest: &SetManifest) -> CatalogSet {
    CatalogSet {
        set_id: manifest.set_id.clone(),
        label: manifest.label.clone(),
        created_unix: manifest.created_unix,
        files: manifest.files.len() as u64,
        bytes: manifest.total_bytes(),
        distinct_chunks: manifest.distinct_chunks().len() as u64,
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BackupOutcome {
    pub manifest: SetManifest,
    /// Chunks physically written by this backup.
    pub chunks_written: u64,
    /// Chunks that already existed on the volume (dedupe).
    pub chunks_reused: u64,
}

fn slugify(label: &str) -> String {
    let mut slug: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    slug = slug
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    slug.truncate(24);
    if slug.is_empty() {
        slug = "set".to_string();
    }
    slug
}

fn root_display_name(root: &Path) -> String {
    // From the *logical* root string, splitting on both separators: a
    // logical root may be Windows-style (C:\Users\…) on any host OS.
    last_path_segment(root)
        .map(|n| slugify(&n))
        .unwrap_or_else(|| "root".to_string())
}

fn new_set_id(label: &str, created_unix: u64) -> Result<String> {
    let rand = random_array::<4>()?;
    Ok(format!(
        "{created_unix}-{}-{}",
        slugify(label),
        hex::encode(&rand)
    ))
}

struct FoundFile {
    set_path: String,
    source: PathBuf,
}

/// Walk the roots (through the capture source) and enumerate regular
/// files. Symlinks and non-regular files are recorded as skipped, never
/// followed and never silent. Set paths are built from the *logical*
/// root only — the resolved (e.g. snapshot device) path is used solely
/// to open files and never leaks into the manifest.
fn enumerate(
    source: &dyn CaptureSource,
    roots: &[PathBuf],
    display_names: &[String],
) -> Result<(Vec<FoundFile>, Vec<SkippedEntry>)> {
    let mut found = Vec::new();
    let mut skipped = Vec::new();
    for (idx, root) in roots.iter().enumerate() {
        let display = &display_names[idx];
        let open_root = source.resolve_root(root)?;
        let meta = fs::metadata(&open_root).map_err(|e| CoreError::SourceUnreadable {
            path: root.clone(),
            source: e,
        })?;
        if meta.is_file() {
            let name = last_path_segment(root).unwrap_or_else(|| "file".to_string());
            found.push(FoundFile {
                set_path: format!("{display}/{name}"),
                source: open_root,
            });
            continue;
        }
        if !meta.is_dir() {
            skipped.push(SkippedEntry {
                path: display.clone(),
                reason: "not a regular file or folder".to_string(),
            });
            continue;
        }
        let mut stack = vec![open_root.clone()];
        while let Some(dir) = stack.pop() {
            let mut entries: Vec<PathBuf> = Vec::new();
            for entry in fs::read_dir(&dir).map_err(|e| io_at(&dir, e))? {
                entries.push(entry.map_err(|e| io_at(&dir, e))?.path());
            }
            entries.sort();
            for path in entries {
                let rel = path
                    .strip_prefix(&open_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let set_path = format!("{display}/{rel}");
                let ftype = fs::symlink_metadata(&path).map_err(|e| io_at(&path, e))?;
                if ftype.file_type().is_symlink() {
                    skipped.push(SkippedEntry {
                        path: set_path,
                        reason: "symbolic link — links are not followed".to_string(),
                    });
                } else if ftype.is_dir() {
                    stack.push(path);
                } else if ftype.is_file() {
                    found.push(FoundFile {
                        set_path,
                        source: path,
                    });
                } else {
                    skipped.push(SkippedEntry {
                        path: set_path,
                        reason: "not a regular file".to_string(),
                    });
                }
            }
        }
    }
    found.sort_by(|a, b| a.set_path.cmp(&b.set_path));
    Ok((found, skipped))
}

/// Back up every regular file under `roots` (files or folders) into a new
/// set on the volume, reading from the live filesystem. Progress is
/// called as (files_done, files_total).
///
/// Failure policy: a source file that cannot be read aborts the backup
/// with `SourceUnreadable` and **no set manifest is written** — chunks
/// already stored stay on the volume as harmless dedupe pool content, but
/// a partial backup never appears as a set.
pub fn backup_tree(
    volume: &UnlockedVolume,
    label: &str,
    roots: &[PathBuf],
    created_unix: u64,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<BackupOutcome> {
    backup_tree_with_source(volume, &LiveSource, label, roots, created_unix, progress)
}

/// Like [`backup_tree`], but reads through a [`CaptureSource`] (S3): the
/// roots are logical paths, the source resolves what to open, and the
/// manifest records the source's capture mode. Failure policy identical
/// to `backup_tree`: an unreadable source aborts with no manifest.
pub fn backup_tree_with_source(
    volume: &UnlockedVolume,
    source: &dyn CaptureSource,
    label: &str,
    roots: &[PathBuf],
    created_unix: u64,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<BackupOutcome> {
    let mut display_names = Vec::new();
    for root in roots {
        let name = root_display_name(root);
        if display_names.contains(&name) {
            return Err(CoreError::RootNameCollision { name });
        }
        display_names.push(name);
    }
    let (found, skipped) = enumerate(source, roots, &display_names)?;
    let total = found.len() as u64;
    let set_id = new_set_id(label, created_unix)?;
    let mut files = Vec::with_capacity(found.len());
    let mut chunks_written = 0u64;
    let mut chunks_reused = 0u64;
    for (i, item) in found.iter().enumerate() {
        let entry = backup_one_file(volume, item, &mut chunks_written, &mut chunks_reused)?;
        files.push(entry);
        progress(i as u64 + 1, total);
    }
    let manifest = SetManifest {
        format_version: SET_FORMAT_VERSION,
        set_id: set_id.clone(),
        label: label.to_string(),
        created_unix,
        roots: display_names,
        capture_mode: source.capture_mode(),
        files,
        skipped,
    };
    write_set_manifest(volume, &manifest)?;
    Ok(BackupOutcome {
        manifest,
        chunks_written,
        chunks_reused,
    })
}

fn backup_one_file(
    volume: &UnlockedVolume,
    item: &FoundFile,
    chunks_written: &mut u64,
    chunks_reused: &mut u64,
) -> Result<SetFileEntry> {
    let meta = fs::metadata(&item.source).map_err(|e| CoreError::SourceUnreadable {
        path: item.source.clone(),
        source: e,
    })?;
    let mtime_unix = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut reader = fs::File::open(&item.source).map_err(|e| CoreError::SourceUnreadable {
        path: item.source.clone(),
        source: e,
    })?;
    let mut hasher = Sha256::new();
    let mut chunks = Vec::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; SET_CHUNK_SIZE];
    loop {
        // Fill the buffer fully (a short read is not EOF for files).
        let mut filled = 0;
        while filled < buf.len() {
            match reader.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => {
                    return Err(CoreError::SourceUnreadable {
                        path: item.source.clone(),
                        source: e,
                    })
                }
            }
        }
        if filled == 0 {
            break;
        }
        let piece = &buf[..filled];
        hasher.update(piece);
        size += filled as u64;
        let existed = volume.chunk_exists(&sha256_hex(piece));
        let id = volume.put_chunk(piece)?;
        if existed {
            *chunks_reused += 1;
        } else {
            *chunks_written += 1;
        }
        chunks.push(id);
        if filled < buf.len() {
            break;
        }
    }
    Ok(SetFileEntry {
        path: item.set_path.clone(),
        size,
        mtime_unix,
        sha256: hex::encode(&hasher.finalize()),
        chunks,
    })
}

fn set_manifest_path(volume: &UnlockedVolume, set_id: &str) -> PathBuf {
    volume.sets_dir().join(format!("{set_id}.json"))
}

pub fn write_set_manifest(volume: &UnlockedVolume, manifest: &SetManifest) -> Result<()> {
    let path = set_manifest_path(volume, &manifest.set_id);
    if path.exists() {
        return Err(CoreError::SetAlreadyExists {
            set_id: manifest.set_id.clone(),
        });
    }
    fs::create_dir_all(volume.sets_dir()).map_err(|e| io_at(&volume.sets_dir(), e))?;
    let json = serde_json::to_string_pretty(manifest).unwrap();
    // Temp + rename, like chunks: a crash never leaves a torn manifest.
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| io_at(&tmp, e))?;
    fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
    Ok(())
}

pub fn read_set_manifest(volume: &UnlockedVolume, set_id: &str) -> Result<SetManifest> {
    let path = set_manifest_path(volume, set_id);
    if !path.exists() {
        return Err(CoreError::SetNotFound {
            set_id: set_id.to_string(),
        });
    }
    let text = fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    serde_json::from_str(&text).map_err(|source| CoreError::Json { path, source })
}

/// All set ids on the volume, from the manifests themselves (never from
/// the catalog — manifests are the source of truth).
pub fn list_set_ids(volume: &UnlockedVolume) -> Result<Vec<String>> {
    let dir = volume.sets_dir();
    let mut ids = Vec::new();
    if dir.exists() {
        for entry in fs::read_dir(&dir).map_err(|e| io_at(&dir, e))? {
            let entry = entry.map_err(|e| io_at(&dir, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.strip_suffix(".json") {
                ids.push(id.to_string());
            }
        }
    }
    ids.sort();
    Ok(ids)
}

/// Set summaries read straight from the manifests.
pub fn list_sets(volume: &UnlockedVolume) -> Result<Vec<CatalogSet>> {
    let mut sets = Vec::new();
    for id in list_set_ids(volume)? {
        sets.push(summarize(&read_set_manifest(volume, &id)?));
    }
    sets.sort_by(|a, b| (a.created_unix, &a.set_id).cmp(&(b.created_unix, &b.set_id)));
    Ok(sets)
}

/// Rebuild `catalog.json` by scanning set manifests only. This is the
/// operation the recovery environment performs when the app (and any
/// database it kept) is gone: the volume alone is enough.
pub fn rebuild_catalog(volume: &UnlockedVolume) -> Result<Catalog> {
    let catalog = Catalog {
        format_version: SET_FORMAT_VERSION,
        sets: list_sets(volume)?,
    };
    let path = volume.catalog_path();
    let json = serde_json::to_string_pretty(&catalog).unwrap();
    fs::write(&path, json).map_err(|e| io_at(&path, e))?;
    Ok(catalog)
}

pub fn read_catalog(volume: &UnlockedVolume) -> Result<Catalog> {
    let path = volume.catalog_path();
    let text = fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    serde_json::from_str(&text).map_err(|source| CoreError::Json { path, source })
}

// ---------------------------------------------------------------------------
// Level-1 verify (the Quick Check's engine logic)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkFailure {
    pub chunk_id: String,
    /// Stable reason code: missing / decrypt_failed / hash_mismatch /
    /// decompress_failed / bad_record (see ChunkCorruptReason) or "io".
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVerifyReport {
    pub set_id: String,
    pub files: usize,
    pub chunks_checked: usize,
    pub chunks_ok: usize,
    /// Total plaintext bytes across the set's files.
    pub plaintext_bytes: u64,
    /// Every failed chunk, named by id. Empty means the set is intact.
    pub failures: Vec<ChunkFailure>,
}

impl SetVerifyReport {
    pub fn passed(&self) -> bool {
        self.failures.is_empty() && self.chunks_checked == self.chunks_ok
    }
}

/// Level-1 Rehearsal over a whole set: fetch, decrypt, decompress, and
/// re-hash every distinct chunk. Read-only on the volume. Progress is
/// called as (chunks_done, chunks_total).
pub fn verify_set(
    volume: &UnlockedVolume,
    set_id: &str,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SetVerifyReport> {
    let manifest = read_set_manifest(volume, set_id)?;
    let distinct: Vec<&str> = manifest.distinct_chunks().into_iter().collect();
    let total = distinct.len() as u64;
    let mut failures = Vec::new();
    let mut ok = 0usize;
    for (i, chunk_id) in distinct.iter().enumerate() {
        match volume.get_chunk(chunk_id) {
            Ok(_) => ok += 1,
            Err(CoreError::ChunkMissing { .. }) => failures.push(ChunkFailure {
                chunk_id: chunk_id.to_string(),
                reason: "missing".to_string(),
            }),
            Err(CoreError::ChunkCorrupt { reason, .. }) => failures.push(ChunkFailure {
                chunk_id: chunk_id.to_string(),
                reason: reason.as_str().to_string(),
            }),
            Err(e) => failures.push(ChunkFailure {
                chunk_id: chunk_id.to_string(),
                reason: format!("io: {e}"),
            }),
        }
        progress(i as u64 + 1, total);
    }
    Ok(SetVerifyReport {
        set_id: set_id.to_string(),
        files: manifest.files.len(),
        chunks_checked: distinct.len(),
        chunks_ok: ok,
        plaintext_bytes: manifest.total_bytes(),
        failures,
    })
}

// ---------------------------------------------------------------------------
// Restore (low level — callers layer the plan-token policy on top)

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreOutcome {
    pub files_written: usize,
    pub bytes_written: u64,
    /// Files whose target already held byte-identical content.
    pub files_already_identical: usize,
}

/// SHA-256 of an existing file's content, or None if it does not exist.
pub fn hash_existing_file(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let mut reader = fs::File::open(path).map_err(|e| io_at(&path.to_path_buf(), e))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| io_at(&path.to_path_buf(), e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(hex::encode(&hasher.finalize())))
}

fn restore_one_file(
    volume: &UnlockedVolume,
    entry: &SetFileEntry,
    dest: &Path,
    allowed_overwrites: &HashSet<String>,
    outcome: &mut RestoreOutcome,
) -> Result<()> {
    match hash_existing_file(dest)? {
        Some(existing) if existing == entry.sha256 => {
            outcome.files_already_identical += 1;
            return Ok(());
        }
        Some(_) if !allowed_overwrites.contains(&entry.path) => {
            return Err(CoreError::RestoreConflict {
                path: entry.path.clone(),
            });
        }
        _ => {}
    }
    // Rebuild in memory chunk by chunk (chunks are ≤1 MiB), then verify the
    // whole-file hash before anything touches the destination: a damaged
    // chunk must produce an error, never a partial or corrupt restored file.
    let mut content = Vec::with_capacity(entry.size as usize);
    for chunk_id in &entry.chunks {
        content.extend_from_slice(&volume.get_chunk(chunk_id)?);
    }
    if content.len() as u64 != entry.size || sha256_hex(&content) != entry.sha256 {
        return Err(CoreError::ChunkCorrupt {
            chunk_id: entry.chunks.first().cloned().unwrap_or_default(),
            reason: crate::error::ChunkCorruptReason::HashMismatch,
        });
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| io_at(&parent.to_path_buf(), e))?;
    }
    // Write via temp + rename so an interrupted restore never leaves a
    // half-written file at the destination.
    let tmp = dest.with_extension("safereturn-tmp");
    fs::write(&tmp, &content).map_err(|e| io_at(&tmp, e))?;
    fs::rename(&tmp, dest).map_err(|e| io_at(&dest.to_path_buf(), e))?;
    outcome.files_written += 1;
    outcome.bytes_written += entry.size;
    Ok(())
}

/// Restore every file of a set under `target_dir` (set-relative layout).
/// Files that already exist with different content are only overwritten
/// if their set path is in `allowed_overwrites`; otherwise the restore
/// stops with `RestoreConflict` before writing that file. Callers: the
/// engine's plan-token flow (S2) computes the approved set from the plan
/// the user confirmed; the File Rehearsal restores into an empty sandbox
/// with an empty overwrite set.
pub fn restore_set(
    volume: &UnlockedVolume,
    set_id: &str,
    target_dir: &Path,
    allowed_overwrites: &HashSet<String>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    let manifest = read_set_manifest(volume, set_id)?;
    restore_files(
        volume,
        &manifest.files,
        target_dir,
        allowed_overwrites,
        progress,
    )
}

pub fn restore_files(
    volume: &UnlockedVolume,
    files: &[SetFileEntry],
    target_dir: &Path,
    allowed_overwrites: &HashSet<String>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    let entries: Vec<(SetFileEntry, PathBuf)> = files
        .iter()
        .map(|f| (f.clone(), target_dir.join(&f.path)))
        .collect();
    restore_entries(volume, &entries, allowed_overwrites, progress)
}

/// Restore (entry, explicit destination) pairs. The overwrite policy is
/// keyed by set path: a destination holding different content is only
/// replaced when the entry's set path is in `allowed_overwrites`.
pub fn restore_entries(
    volume: &UnlockedVolume,
    entries: &[(SetFileEntry, PathBuf)],
    allowed_overwrites: &HashSet<String>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    let total = entries.len() as u64;
    let mut outcome = RestoreOutcome::default();
    for (i, (entry, dest)) in entries.iter().enumerate() {
        restore_one_file(volume, entry, dest, allowed_overwrites, &mut outcome)?;
        progress(i as u64 + 1, total);
    }
    Ok(outcome)
}

/// Restore a single file of a set to an exact destination path.
pub fn restore_file(
    volume: &UnlockedVolume,
    set_id: &str,
    path_in_set: &str,
    dest: &Path,
    allow_overwrite: bool,
) -> Result<RestoreOutcome> {
    let manifest = read_set_manifest(volume, set_id)?;
    let entry = manifest
        .file(path_in_set)
        .ok_or_else(|| CoreError::FileNotInSet {
            set_id: set_id.to_string(),
            path: path_in_set.to_string(),
        })?;
    let mut allowed = HashSet::new();
    if allow_overwrite {
        allowed.insert(entry.path.clone());
    }
    let mut outcome = RestoreOutcome::default();
    restore_one_file(volume, entry, dest, &allowed, &mut outcome)?;
    Ok(outcome)
}

/// Map of set path → what restoring it would meet at the target, used by
/// the engine's restore planning (and by tests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetState {
    /// Nothing at the destination.
    Absent,
    /// Destination already holds byte-identical content.
    Identical,
    /// Destination holds different content; restoring would overwrite it.
    Differs,
}

/// Per-file target states for a whole set, keyed by set path.
pub fn plan_target_states(
    manifest: &SetManifest,
    target_dir: &Path,
) -> Result<BTreeMap<String, TargetState>> {
    let mut map = BTreeMap::new();
    for entry in &manifest.files {
        let dest = target_dir.join(&entry.path);
        let state = match hash_existing_file(&dest)? {
            None => TargetState::Absent,
            Some(h) if h == entry.sha256 => TargetState::Identical,
            Some(_) => TargetState::Differs,
        };
        map.insert(entry.path.clone(), state);
    }
    Ok(map)
}
