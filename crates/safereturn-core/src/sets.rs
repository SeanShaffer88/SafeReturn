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
use crate::restore_safety::{
    inspect_directory, inspect_file, join_relative, path_issues, validate_paths,
    validate_relative_path,
};
use crate::volume::{sha256_hex, UnlockedVolume};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io::{Read, Write};
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
    /// System facts section (S3): present on system backup sets,
    /// absent (the field is omitted entirely) on plain file sets and
    /// on every pre-S3 manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<crate::system::SystemFacts>,
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

/// Validate all recorded destinations before planning or writing any of them.
/// Checking the complete set also prevents a selected path from ambiguously
/// matching a duplicate or an alias elsewhere in the manifest.
pub(crate) fn validate_restore_manifest(manifest: &SetManifest) -> Result<()> {
    if manifest.format_version != SET_FORMAT_VERSION {
        return Err(CoreError::InvalidSetManifest {
            set_id: manifest.set_id.clone(),
            reason: format!(
                "format version {} is not supported",
                manifest.format_version
            ),
        });
    }
    manifest
        .files
        .iter()
        .try_fold(0u64, |total, file| total.checked_add(file.size))
        .ok_or_else(|| CoreError::InvalidSetManifest {
            set_id: manifest.set_id.clone(),
            reason: "the total recorded file size overflows".to_string(),
        })?;
    validate_paths(manifest.files.iter().map(|f| f.path.as_str()))
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
    backup_tree_with_source_progress(
        volume,
        source,
        label,
        roots,
        created_unix,
        &mut |phase, done, total| {
            if phase == BackupPhase::Copying {
                progress(done, total);
            }
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupPhase {
    Copying,
    Verifying,
}

/// Internal phased variant so the engine can report the separate read-back
/// phase without changing the public file-copy progress callback.
pub(crate) fn backup_tree_with_source_progress(
    volume: &UnlockedVolume,
    source: &dyn CaptureSource,
    label: &str,
    roots: &[PathBuf],
    created_unix: u64,
    progress: &mut dyn FnMut(BackupPhase, u64, u64),
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
        let entry = backup_one_file(volume, item, &mut chunks_written, &mut chunks_reused)
            .map_err(|error| match error {
                CoreError::SourceUnreadable { .. } => error,
                other => CoreError::BackupWriteFailed {
                    detail: other.to_string(),
                },
            })?;
        files.push(entry);
        progress(BackupPhase::Copying, i as u64 + 1, total);
    }
    let manifest = SetManifest {
        format_version: SET_FORMAT_VERSION,
        set_id: set_id.clone(),
        label: label.to_string(),
        created_unix,
        roots: display_names,
        capture_mode: source.capture_mode(),
        system: None,
        files,
        skipped,
    };
    // Re-read *all* referenced chunks, including reused ones, and prove
    // their ordered contents match each file's captured size and hash.
    // A damaged dedupe hit must not become a successful new backup.
    let report = verify_manifest(volume, &manifest, &mut |done, total| {
        progress(BackupPhase::Verifying, done, total);
    })
    .map_err(|e| CoreError::BackupVerificationFailed {
        detail: e.to_string(),
    })?;
    if !report.passed() {
        return Err(CoreError::BackupVerificationFailed {
            detail: report.failure_summary(),
        });
    }
    // Only publish a manifest after its serialized bytes have also been
    // flushed and read back. Earlier failures leave no partial set.
    write_set_manifest(volume, &manifest).map_err(|error| match error {
        CoreError::BackupVerificationFailed { .. } => error,
        other => CoreError::BackupWriteFailed {
            detail: other.to_string(),
        },
    })?;
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

fn set_manifest_path(volume: &UnlockedVolume, set_id: &str) -> Result<PathBuf> {
    // Set IDs generated by this engine use these characters only. In
    // particular, never join caller-supplied separators or drive prefixes.
    if set_id.is_empty()
        || validate_relative_path(set_id).is_err()
        || !set_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(CoreError::InvalidSetManifest {
            set_id: set_id.to_string(),
            reason: "the set ID contains characters that cannot be used as a safe manifest name"
                .to_string(),
        });
    }
    Ok(volume.sets_dir().join(format!("{set_id}.json")))
}

pub fn write_set_manifest(volume: &UnlockedVolume, manifest: &SetManifest) -> Result<()> {
    write_set_manifest_inner(volume, manifest, |_| Ok(()))
}

// The hook is a no-op in production; tests use it to inject a failed
// read-back between the flush and publication without racing the disk.
fn write_set_manifest_inner(
    volume: &UnlockedVolume,
    manifest: &SetManifest,
    after_flush: impl FnOnce(&Path) -> Result<()>,
) -> Result<()> {
    let path = set_manifest_path(volume, &manifest.set_id)?;
    if path.exists() {
        return Err(CoreError::SetAlreadyExists {
            set_id: manifest.set_id.clone(),
        });
    }
    fs::create_dir_all(volume.sets_dir()).map_err(|e| io_at(&volume.sets_dir(), e))?;
    let json = serde_json::to_string_pretty(manifest).unwrap();
    // Read back the flushed bytes before the atomic publication step. A
    // uniquely named temp file prevents concurrent writers sharing one
    // partial manifest; stray temp files are not listed as backup sets.
    let tmp = path.with_extension(format!("json.{}.tmp", hex::encode(&random_array::<8>()?)));
    let mut created = false;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| io_at(&tmp, e))?;
        created = true;
        file.write_all(json.as_bytes())
            .map_err(|e| io_at(&tmp, e))?;
        file.sync_all().map_err(|e| io_at(&tmp, e))?;
        drop(file);
        after_flush(&tmp)?;
        let saved = fs::read(&tmp).map_err(|e| io_at(&tmp, e))?;
        if saved != json.as_bytes() {
            return Err(CoreError::BackupVerificationFailed {
                detail: "the saved manifest does not match the data that was written".to_string(),
            });
        }
        fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Attach gathered system facts to an existing set (S3). Facts are
/// validated first; a set that already carries a system section keeps
/// it — recorded facts are never silently replaced. The manifest is
/// rewritten with the same temp-file + rename discipline as creation.
pub fn attach_system_facts(
    volume: &UnlockedVolume,
    set_id: &str,
    facts: crate::system::SystemFacts,
) -> Result<SetManifest> {
    facts.validate()?;
    let mut manifest = read_set_manifest(volume, set_id)?;
    if manifest.system.is_some() {
        return Err(CoreError::SystemFactsAlreadyPresent {
            set_id: set_id.to_string(),
        });
    }
    manifest.system = Some(facts);
    rewrite_set_manifest(volume, &manifest)?;
    Ok(manifest)
}

/// Overwrite an existing set manifest (temp + rename). Only for
/// engine-internal updates like attaching system facts; creation goes
/// through `write_set_manifest`, which refuses existing ids.
fn rewrite_set_manifest(volume: &UnlockedVolume, manifest: &SetManifest) -> Result<()> {
    let path = set_manifest_path(volume, &manifest.set_id)?;
    let json = serde_json::to_string_pretty(manifest).unwrap();
    let tmp = path.with_extension(format!("json.{}.tmp", hex::encode(&random_array::<16>()?)));
    let mut created = false;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| io_at(&tmp, e))?;
        created = true;
        file.write_all(json.as_bytes())
            .map_err(|e| io_at(&tmp, e))?;
        file.sync_all().map_err(|e| io_at(&tmp, e))?;
        drop(file);
        fs::rename(&tmp, &path).map_err(|e| io_at(&path, e))?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn read_set_manifest(volume: &UnlockedVolume, set_id: &str) -> Result<SetManifest> {
    let path = set_manifest_path(volume, set_id)?;
    if !path.exists() {
        return Err(CoreError::SetNotFound {
            set_id: set_id.to_string(),
        });
    }
    let text = fs::read_to_string(&path).map_err(|e| io_at(&path, e))?;
    let manifest: SetManifest =
        serde_json::from_str(&text).map_err(|source| CoreError::Json { path, source })?;
    if manifest.format_version != SET_FORMAT_VERSION {
        return Err(CoreError::InvalidSetManifest {
            set_id: set_id.to_string(),
            reason: format!(
                "format version {} is not supported (expected {})",
                manifest.format_version, SET_FORMAT_VERSION
            ),
        });
    }
    if manifest.set_id != set_id {
        return Err(CoreError::InvalidSetManifest {
            set_id: set_id.to_string(),
            reason: format!("the manifest identifies itself as {}", manifest.set_id),
        });
    }
    manifest
        .files
        .iter()
        .try_fold(0u64, |sum, file| sum.checked_add(file.size))
        .ok_or_else(|| CoreError::InvalidSetManifest {
            set_id: set_id.to_string(),
            reason: "the total recorded file size overflows".to_string(),
        })?;
    Ok(manifest)
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

/// A file that cannot be assembled to its recorded size and SHA-256.
/// Reasons are stable codes: `chunk_unavailable`, `size_mismatch`,
/// `hash_mismatch`, `unsafe_path`, `duplicate_path`, or `conflicting_path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFailure {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetVerifyReport {
    pub set_id: String,
    pub files: usize,
    /// Unique chunk ids checked, even when the same chunk is used by
    /// multiple files or more than once in a file.
    pub chunks_checked: usize,
    pub chunks_ok: usize,
    /// Total plaintext bytes recorded across the set's files.
    pub plaintext_bytes: u64,
    /// Every unreadable or damaged chunk, named by id.
    pub failures: Vec<ChunkFailure>,
    /// Files whose ordered chunks do not reproduce the recorded file,
    /// or which could not be checked because a chunk was unavailable.
    pub file_failures: Vec<FileFailure>,
}

impl SetVerifyReport {
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
            && self.file_failures.is_empty()
            && self.chunks_checked == self.chunks_ok
    }

    fn failure_summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(first) = self.failures.first() {
            parts.push(format!(
                "{} chunk(s) could not be read (first: {} — {})",
                self.failures.len(),
                first.chunk_id,
                first.reason
            ));
        }
        if let Some(first) = self.file_failures.first() {
            parts.push(format!(
                "{} file check(s) failed (first: {} — {})",
                self.file_failures.len(),
                first.path,
                first.reason
            ));
        }
        parts.join("; ")
    }
}

/// Level-1 check: decrypt and hash the referenced chunks and stream them
/// in file order to check each file's recorded length and whole-file hash.
/// Progress counts chunk *references* processed (readable duplicates are
/// reread), while the report counts distinct chunk ids. The backup is read-only.
/// This checks consistency with the current manifest, not its authenticity
/// or whether entries were removed from it after capture.
pub fn verify_set(
    volume: &UnlockedVolume,
    set_id: &str,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SetVerifyReport> {
    let manifest = read_set_manifest(volume, set_id)?;
    verify_manifest(volume, &manifest, progress)
}

/// Shared by Quick Check and backup finalization. Only one chunk is held
/// at a time, so a large file does not need to fit in memory.
fn verify_manifest(
    volume: &UnlockedVolume,
    manifest: &SetManifest,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<SetVerifyReport> {
    let invalid = |reason: &str| CoreError::InvalidSetManifest {
        set_id: manifest.set_id.clone(),
        reason: reason.to_string(),
    };
    let plaintext_bytes = manifest
        .files
        .iter()
        .try_fold(0u64, |sum, f| sum.checked_add(f.size))
        .ok_or_else(|| invalid("the total recorded file size overflows"))?;
    let total = manifest
        .files
        .iter()
        .try_fold(0u64, |sum, f| {
            u64::try_from(f.chunks.len())
                .ok()
                .and_then(|count| sum.checked_add(count))
        })
        .ok_or_else(|| invalid("the total number of chunk references overflows"))?;

    let distinct = manifest.distinct_chunks();
    let mut failures: BTreeMap<String, String> = BTreeMap::new();
    let mut checks = Vec::with_capacity(manifest.files.len());
    let mut done = 0u64;
    for file in &manifest.files {
        let mut hasher = Sha256::new();
        let mut actual_size = 0u64;
        let mut unavailable = false;
        for chunk_id in &file.chunks {
            if failures.contains_key(chunk_id) {
                unavailable = true;
            } else {
                match volume.get_chunk(chunk_id) {
                    Ok(bytes) => {
                        actual_size = actual_size
                            .checked_add(bytes.len() as u64)
                            .ok_or_else(|| invalid("assembled file size overflows"))?;
                        hasher.update(&bytes);
                    }
                    Err(e) => {
                        let reason = match e {
                            CoreError::ChunkMissing { .. } => "missing".to_string(),
                            CoreError::ChunkCorrupt { reason, .. } => reason.as_str().to_string(),
                            other => format!("io: {other}"),
                        };
                        failures.insert(chunk_id.clone(), reason);
                        unavailable = true;
                    }
                }
            }
            done += 1;
            progress(done, total);
        }
        let reason = if unavailable {
            None // assigned below, including failures discovered in later files
        } else if actual_size != file.size {
            Some("size_mismatch")
        } else if hex::encode(&hasher.finalize()) != file.sha256 {
            Some("hash_mismatch")
        } else {
            None
        };
        checks.push(reason);
    }

    let mut file_failures: Vec<FileFailure> =
        path_issues(manifest.files.iter().map(|f| f.path.as_str()))
            .into_iter()
            .map(|issue| FileFailure {
                path: issue.path,
                reason: issue.code.to_string(),
            })
            .collect();
    for (file, reason) in manifest.files.iter().zip(checks) {
        let reason = if file.chunks.iter().any(|id| failures.contains_key(id)) {
            Some("chunk_unavailable")
        } else {
            reason
        };
        if let Some(reason) = reason {
            file_failures.push(FileFailure {
                path: file.path.clone(),
                reason: reason.to_string(),
            });
        }
    }
    let chunks_checked = distinct.len();
    let chunks_ok = chunks_checked - failures.len();
    Ok(SetVerifyReport {
        set_id: manifest.set_id.clone(),
        files: manifest.files.len(),
        chunks_checked,
        chunks_ok,
        plaintext_bytes,
        failures: failures
            .into_iter()
            .map(|(chunk_id, reason)| ChunkFailure { chunk_id, reason })
            .collect(),
        file_failures,
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

/// SHA-256 of an existing regular file's content, or None if absent.
/// Existing links, reparse points, and non-regular files are refused rather
/// than intentionally followed. The inspection is not race-free.
pub fn hash_existing_file(path: &Path) -> Result<Option<String>> {
    if !inspect_file(path)? {
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
    expected: Option<&Option<String>>,
    outcome: &mut RestoreOutcome,
) -> Result<()> {
    restore_one_file_inner(
        volume,
        entry,
        dest,
        allowed_overwrites,
        expected,
        outcome,
        || {},
    )
}

// The hook is a no-op in production. A test uses it to create a competing
// destination after the last check and exercise no-clobber publication.
fn restore_one_file_inner(
    volume: &UnlockedVolume,
    entry: &SetFileEntry,
    dest: &Path,
    allowed_overwrites: &HashSet<String>,
    expected: Option<&Option<String>>,
    outcome: &mut RestoreOutcome,
    before_publish: impl FnOnce(),
) -> Result<()> {
    validate_relative_path(&entry.path)?;
    let initial = hash_existing_file(dest)?;
    if expected.is_some_and(|planned| *planned != initial) {
        return Err(CoreError::RestoreTargetChanged {
            path: entry.path.clone(),
        });
    }
    match &initial {
        Some(existing) if existing == &entry.sha256 => {
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

    let parent = dest.parent().unwrap_or_else(|| Path::new(""));
    inspect_directory(parent)?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|e| io_at(&parent.to_path_buf(), e))?;
    }
    inspect_directory(parent)?;

    // A random, exclusively created staging file never truncates an
    // unrelated existing file. Do not allocate from the untrusted recorded
    // file size; write and hash one decoded chunk at a time instead.
    let tmp = parent.join(format!(
        ".safereturn-{}.tmp",
        hex::encode(&random_array::<16>()?)
    ));
    let mut created = false;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| io_at(&tmp, e))?;
        created = true;
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        for chunk_id in &entry.chunks {
            let bytes = volume.get_chunk(chunk_id)?;
            size = size
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| CoreError::ChunkCorrupt {
                    chunk_id: chunk_id.clone(),
                    reason: crate::error::ChunkCorruptReason::HashMismatch,
                })?;
            if size > entry.size {
                return Err(CoreError::ChunkCorrupt {
                    chunk_id: chunk_id.clone(),
                    reason: crate::error::ChunkCorruptReason::HashMismatch,
                });
            }
            hasher.update(&bytes);
            file.write_all(&bytes).map_err(|e| io_at(&tmp, e))?;
        }
        if size != entry.size || hex::encode(&hasher.finalize()) != entry.sha256 {
            return Err(CoreError::ChunkCorrupt {
                chunk_id: entry.chunks.first().cloned().unwrap_or_default(),
                reason: crate::error::ChunkCorruptReason::HashMismatch,
            });
        }
        file.sync_all().map_err(|e| io_at(&tmp, e))?;
        drop(file);
        if hash_existing_file(&tmp)?.as_deref() != Some(entry.sha256.as_str()) {
            return Err(io_at(
                &tmp,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the staged file did not match the backup when read back",
                ),
            ));
        }
        // Recheck immediately before publication. This reduces the window
        // for surprise overwrites, but cannot eliminate concurrent races.
        if hash_existing_file(dest)? != initial {
            return Err(CoreError::RestoreTargetChanged {
                path: entry.path.clone(),
            });
        }
        before_publish();
        if initial.is_none() {
            // Hard-link publication is atomic and fails if a new destination
            // has appeared. Some filesystems do not support hard links; those
            // must fail rather than fall back to a clobbering rename.
            match fs::hard_link(&tmp, dest) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(CoreError::RestoreTargetChanged {
                        path: entry.path.clone(),
                    });
                }
                Err(e) => return Err(io_at(&dest.to_path_buf(), e)),
            }
            fs::remove_file(&tmp).map_err(|e| io_at(&tmp, e))?;
        } else {
            fs::rename(&tmp, dest).map_err(|e| io_at(&dest.to_path_buf(), e))?;
        }
        outcome.files_written += 1;
        outcome.bytes_written += entry.size;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&tmp);
    }
    result
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
    validate_restore_manifest(&manifest)?;
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
    validate_paths(files.iter().map(|f| f.path.as_str()))?;
    let entries: Vec<(SetFileEntry, PathBuf)> = files
        .iter()
        .map(|f| Ok((f.clone(), join_relative(target_dir, &f.path)?)))
        .collect::<Result<_>>()?;
    restore_entries(volume, &entries, allowed_overwrites, progress)
}

/// Restore (entry, explicit destination) pairs. The overwrite policy is
/// keyed by set path: a destination holding different content is only
/// replaced when the entry's set path is in `allowed_overwrites`. Explicit
/// destinations are caller-selected; this API does not impose a base folder.
pub fn restore_entries(
    volume: &UnlockedVolume,
    entries: &[(SetFileEntry, PathBuf)],
    allowed_overwrites: &HashSet<String>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    restore_entries_inner(volume, entries, allowed_overwrites, None, progress)
}

/// The engine's plan also retains the exact destination hashes. Recheck each
/// one during the job as well as the full preflight before the job starts.
pub(crate) fn restore_entries_with_snapshots(
    volume: &UnlockedVolume,
    entries: &[(SetFileEntry, PathBuf)],
    allowed_overwrites: &HashSet<String>,
    expected: &BTreeMap<String, Option<String>>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    restore_entries_inner(
        volume,
        entries,
        allowed_overwrites,
        Some(expected),
        progress,
    )
}

fn restore_entries_inner(
    volume: &UnlockedVolume,
    entries: &[(SetFileEntry, PathBuf)],
    allowed_overwrites: &HashSet<String>,
    expected: Option<&BTreeMap<String, Option<String>>>,
    progress: &mut dyn FnMut(u64, u64),
) -> Result<RestoreOutcome> {
    // Validate the entire scope and inspect existing path components before
    // writing any entry. Explicit destinations may be on different volumes,
    // so compare their full lexical names here, not just their set paths.
    let mut destinations = BTreeMap::<String, &PathBuf>::new();
    let mut bytes = 0u64;
    for (entry, dest) in entries {
        validate_relative_path(&entry.path)?;
        bytes = bytes
            .checked_add(entry.size)
            .ok_or_else(|| CoreError::InvalidSetManifest {
                set_id: "requested restore".to_string(),
                reason: "the total recorded file size overflows".to_string(),
            })?;
        inspect_file(dest)?;
        let key = dest.to_string_lossy().replace('\\', "/").to_lowercase();
        if let Some(previous) = destinations.insert(key, dest) {
            return Err(CoreError::UnsafeRestoreDestination {
                path: dest.clone(),
                reason: format!(
                    "it conflicts with another requested destination ({})",
                    previous.display()
                ),
            });
        }
        if let Some(snapshots) = expected {
            if !snapshots.contains_key(&entry.path) {
                return Err(CoreError::RestoreTargetChanged {
                    path: entry.path.clone(),
                });
            }
        }
    }
    for (key, dest) in &destinations {
        let mut parent = key.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if destinations.contains_key(prefix) {
                return Err(CoreError::UnsafeRestoreDestination {
                    path: (*dest).clone(),
                    reason: "another requested file is also a parent folder".to_string(),
                });
            }
            parent = prefix;
        }
    }
    let total = entries.len() as u64;
    let mut outcome = RestoreOutcome::default();
    for (i, (entry, dest)) in entries.iter().enumerate() {
        let snapshot = expected.and_then(|snapshots| snapshots.get(&entry.path));
        restore_one_file(
            volume,
            entry,
            dest,
            allowed_overwrites,
            snapshot,
            &mut outcome,
        )?;
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
    validate_restore_manifest(&manifest)?;
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
    restore_entries(
        volume,
        &[(entry.clone(), dest.to_path_buf())],
        &allowed,
        &mut |_, _| {},
    )
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
    validate_restore_manifest(manifest)?;
    let mut map = BTreeMap::new();
    for entry in &manifest.files {
        let dest = join_relative(target_dir, &entry.path)?;
        let state = match hash_existing_file(&dest)? {
            None => TargetState::Absent,
            Some(h) if h == entry.sha256 => TargetState::Identical,
            Some(_) => TargetState::Differs,
        };
        map.insert(entry.path.clone(), state);
    }
    Ok(map)
}

#[cfg(test)]
mod finalization_tests {
    use super::*;
    use crate::volume::Volume;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn a_destination_created_after_the_last_check_is_not_clobbered() {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "safereturn-restore-race-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (locked, key) = Volume::create(root.join("volume"), "test password", 1).unwrap();
        let volume = locked.unlock_with_recovery_key(&key).unwrap();
        let bytes = b"backed-up bytes";
        let entry = SetFileEntry {
            path: "source/file.txt".to_string(),
            size: bytes.len() as u64,
            mtime_unix: 0,
            sha256: sha256_hex(bytes),
            chunks: vec![volume.put_chunk(bytes).unwrap()],
        };
        let dest = root.join("out/file.txt");
        let mut outcome = RestoreOutcome::default();
        let error = restore_one_file_inner(
            &volume,
            &entry,
            &dest,
            &HashSet::new(),
            None,
            &mut outcome,
            || fs::write(&dest, b"newly arrived file").unwrap(),
        )
        .unwrap_err();
        assert!(matches!(error, CoreError::RestoreTargetChanged { .. }));
        assert_eq!(fs::read(&dest).unwrap(), b"newly arrived file");
        assert_eq!(outcome.files_written, 0);
        assert_eq!(fs::read_dir(root.join("out")).unwrap().count(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn damaged_or_unreadable_staged_manifest_is_never_published() {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "safereturn-manifest-readback-{}-{n}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let (locked, key) = Volume::create(&root, "test password", 1).unwrap();
        let volume = locked.unlock_with_recovery_key(&key).unwrap();
        let manifest = SetManifest {
            format_version: SET_FORMAT_VERSION,
            set_id: "readback-test".to_string(),
            label: "test".to_string(),
            created_unix: 1,
            roots: vec![],
            capture_mode: CaptureMode::Live,
            system: None,
            files: vec![],
            skipped: vec![],
        };
        for remove in [false, true] {
            let err = write_set_manifest_inner(&volume, &manifest, |tmp| {
                if remove {
                    fs::remove_file(tmp).map_err(|e| io_at(&tmp.to_path_buf(), e))?;
                } else {
                    fs::write(tmp, b"damaged manifest")
                        .map_err(|e| io_at(&tmp.to_path_buf(), e))?;
                }
                Ok(())
            })
            .unwrap_err();
            if remove {
                assert!(matches!(err, CoreError::Io { .. }));
            } else {
                assert!(matches!(err, CoreError::BackupVerificationFailed { .. }));
            }
            assert!(!root.join("sets/readback-test.json").exists());
            assert!(list_set_ids(&volume).unwrap().is_empty());
            assert_eq!(fs::read_dir(root.join("sets")).unwrap().count(), 0);
        }
        let _ = fs::remove_dir_all(root);
    }
}
