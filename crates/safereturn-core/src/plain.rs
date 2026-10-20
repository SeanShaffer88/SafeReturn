//! The original S1 prototype, kept intact as the plain (unencrypted)
//! reference implementation: content-addressed chunk store + manifest +
//! Level-1 rehearsal (verify). Fixed-size chunking, SHA-256, no
//! compression/encryption. Its tests (tests/rehearsal.rs) still pin its
//! behavior. The production encrypted store lives in `volume`/`sets`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const CHUNK_SIZE: usize = 64 * 1024;

pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FileEntry {
    pub path: String,
    /// Ordered chunk hashes making up the file.
    pub chunks: Vec<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub backup_id: String,
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VerifyReport {
    pub chunks_checked: usize,
    pub chunks_ok: usize,
    /// Chunk hashes that are missing or whose content no longer matches.
    pub corrupt: Vec<String>,
}

impl VerifyReport {
    pub fn passed(&self) -> bool {
        self.corrupt.is_empty() && self.chunks_checked == self.chunks_ok
    }
}

pub struct ChunkStore {
    root: PathBuf,
}

impl ChunkStore {
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("chunks"))?;
        Ok(Self { root })
    }

    fn chunk_path(&self, hash: &str) -> PathBuf {
        // Fan out by first 2 chars so no single directory holds everything.
        self.root.join("chunks").join(&hash[..2]).join(hash)
    }

    pub fn put(&self, data: &[u8]) -> std::io::Result<String> {
        let hash = sha256_hex(data);
        let path = self.chunk_path(&hash);
        if !path.exists() {
            fs::create_dir_all(path.parent().unwrap())?;
            fs::write(&path, data)?;
        }
        Ok(hash)
    }

    pub fn get(&self, hash: &str) -> std::io::Result<Vec<u8>> {
        fs::read(self.chunk_path(hash))
    }

    /// Back up every file under `source_dir` (recursively) into the store.
    pub fn backup_dir(&self, backup_id: &str, source_dir: &Path) -> std::io::Result<Manifest> {
        let mut files = Vec::new();
        let mut stack = vec![source_dir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.is_file() {
                    let data = fs::read(&p)?;
                    let mut chunks = Vec::new();
                    if data.is_empty() {
                        // Record emptiness explicitly; zero chunks is the encoding.
                    } else {
                        for chunk in data.chunks(CHUNK_SIZE) {
                            chunks.push(self.put(chunk)?);
                        }
                    }
                    files.push(FileEntry {
                        path: p
                            .strip_prefix(source_dir)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                        chunks,
                        size: data.len() as u64,
                    });
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let manifest = Manifest {
            backup_id: backup_id.to_string(),
            files,
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(self.root.join(format!("manifest-{backup_id}.json")), json)?;
        Ok(manifest)
    }

    /// Restore a single file from the manifest to `dest`. Proves file-level restore.
    pub fn restore_file(
        &self,
        manifest: &Manifest,
        rel_path: &str,
        dest: &Path,
    ) -> std::io::Result<()> {
        let entry = manifest
            .files
            .iter()
            .find(|f| f.path == rel_path)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "file not in manifest")
            })?;
        let mut out = Vec::with_capacity(entry.size as usize);
        for hash in &entry.chunks {
            out.extend_from_slice(&self.get(hash)?);
        }
        if out.len() as u64 != entry.size {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "restored size mismatch",
            ));
        }
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(dest, out)
    }

    /// Level-1 Rehearsal: re-hash every distinct chunk in the manifest.
    /// This is the exact logic the UI's "Quick Check" will call.
    pub fn verify(&self, manifest: &Manifest) -> VerifyReport {
        let mut seen: HashMap<&str, bool> = HashMap::new();
        for file in &manifest.files {
            for hash in &file.chunks {
                if seen.contains_key(hash.as_str()) {
                    continue;
                }
                let ok = match self.get(hash) {
                    Ok(data) => sha256_hex(&data) == *hash,
                    Err(_) => false,
                };
                seen.insert(hash, ok);
            }
        }
        let corrupt: Vec<String> = seen
            .iter()
            .filter(|(_, ok)| !**ok)
            .map(|(h, _)| h.to_string())
            .collect();
        VerifyReport {
            chunks_checked: seen.len(),
            chunks_ok: seen.len() - corrupt.len(),
            corrupt,
        }
    }
}
