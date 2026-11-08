//! Checks shared by restore and rehearsal. Manifests are plaintext and must
//! not be trusted as filesystem paths.
//!
//! These are conservative lexical and point-in-time filesystem checks, not
//! a race-free filesystem sandbox. A directory or file can be replaced after
//! inspection; see the restore-safety documentation before relying on them.

use crate::error::{io_at, CoreError, Result};
use std::collections::BTreeMap;
use std::fs::{self, Metadata};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct PathIssue {
    pub path: String,
    pub code: &'static str,
    pub detail: String,
}

/// Accept only an unambiguous, slash-separated relative path that is also
/// usable as a normal Win32 path. This deliberately rejects some filenames
/// legal on other platforms rather than silently changing their meaning.
fn invalid_path_reason(path: &str) -> Option<&'static str> {
    if path.is_empty() {
        return Some("the path is empty");
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Some("empty, current-folder, and parent-folder components are not allowed");
        }
        if part.ends_with(' ') || part.ends_with('.') {
            return Some("a component ends in a space or dot, which Windows may ignore");
        }
        if part
            .chars()
            .any(|c| c <= '\u{1f}' || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return Some(
                "a component contains a Windows separator, stream, or forbidden character",
            );
        }
        // Windows treats these as device names even with extensions; it can
        // also ignore spaces immediately before the first dot.
        let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ');
        let upper = stem.to_uppercase();
        if matches!(
            upper.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
        ) || ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        }) {
            return Some("a component is a reserved Windows device name");
        }
    }
    None
}

pub(crate) fn validate_relative_path(path: &str) -> Result<()> {
    if let Some(reason) = invalid_path_reason(path) {
        return Err(CoreError::UnsafeRestorePath {
            path: path.to_string(),
            reason: reason.to_string(),
        });
    }
    Ok(())
}

pub(crate) fn join_relative(base: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    Ok(base.join(relative))
}

/// Detect exact duplicates, common case-insensitive file *and directory*
/// aliases, and a recorded file that is also a parent directory of another
/// file. Unicode lowercase approximates but does not reproduce filesystem
/// case tables or detect every short-name and filesystem-specific alias.
pub(crate) fn path_issues<'a>(paths: impl IntoIterator<Item = &'a str>) -> Vec<PathIssue> {
    let mut issues = Vec::new();
    let mut names = BTreeMap::<String, String>::new();
    let mut directories = BTreeMap::<String, String>::new();
    for path in paths {
        if let Some(reason) = invalid_path_reason(path) {
            issues.push(PathIssue {
                path: path.to_string(),
                code: "unsafe_path",
                detail: reason.to_string(),
            });
            continue;
        }
        // Different spellings of an ancestor can otherwise silently merge
        // separate directories on a case-insensitive destination even when
        // their leaf filenames do not collide.
        for (index, _) in path.match_indices('/') {
            let directory = &path[..index];
            let key = directory.to_lowercase();
            if let Some(previous) = directories.get(&key) {
                if previous != directory {
                    issues.push(PathIssue {
                        path: path.to_string(),
                        code: "conflicting_path",
                        detail: format!(
                            "the directory {directory:?} aliases the recorded directory {previous:?}"
                        ),
                    });
                    break;
                }
            } else {
                directories.insert(key, directory.to_string());
            }
        }
        let key = path.to_lowercase();
        if let Some(previous) = names.get(&key) {
            issues.push(PathIssue {
                path: path.to_string(),
                code: if previous == path {
                    "duplicate_path"
                } else {
                    "conflicting_path"
                },
                detail: format!("it conflicts with the recorded path {previous:?}"),
            });
        } else {
            names.insert(key, path.to_string());
        }
    }
    for (key, path) in &names {
        let mut parent = key.as_str();
        while let Some((prefix, _)) = parent.rsplit_once('/') {
            if let Some(previous) = names.get(prefix) {
                issues.push(PathIssue {
                    path: path.clone(),
                    code: "conflicting_path",
                    detail: format!("the recorded file {previous:?} is also a parent folder"),
                });
                break;
            }
            parent = prefix;
        }
    }
    issues
}

pub(crate) fn validate_paths<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<()> {
    if let Some(issue) = path_issues(paths).into_iter().next() {
        return Err(CoreError::UnsafeRestorePath {
            path: issue.path,
            reason: issue.detail,
        });
    }
    Ok(())
}

/// Recognize filesystem links and, on Windows, all reparse-point types.
/// Call only with metadata obtained without following the final component.
pub(crate) fn is_link_or_reparse(meta: &Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Inspect each existing ancestor without following the final component.
/// Returns whether the final component exists. This does not lock any path:
/// another process can change it between checks and subsequent filesystem IO.
fn inspect_path(path: &Path, final_is_directory: bool) -> Result<bool> {
    if path.as_os_str().is_empty() {
        return Ok(true); // the current directory, for a relative file name
    }
    let mut final_exists = false;
    let ancestors: Vec<_> = path
        .ancestors()
        .filter(|p| !p.as_os_str().is_empty())
        .collect();
    for component in ancestors.into_iter().rev() {
        match fs::symlink_metadata(component) {
            Ok(meta) => {
                if is_link_or_reparse(&meta) {
                    return Err(CoreError::UnsafeRestoreDestination {
                        path: component.to_path_buf(),
                        reason: "it is a symbolic link or reparse point".to_string(),
                    });
                }
                let final_component = component == path;
                if (final_component && !final_is_directory && !meta.is_file())
                    || ((!final_component || final_is_directory) && !meta.is_dir())
                {
                    return Err(CoreError::UnsafeRestoreDestination {
                        path: component.to_path_buf(),
                        reason: if final_component && !final_is_directory {
                            "it is not a regular file"
                        } else {
                            "it is not a directory"
                        }
                        .to_string(),
                    });
                }
                if final_component {
                    final_exists = true;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_at(&component.to_path_buf(), e)),
        }
    }
    Ok(final_exists)
}

pub(crate) fn inspect_file(path: &Path) -> Result<bool> {
    inspect_path(path, false)
}

pub(crate) fn inspect_directory(path: &Path) -> Result<bool> {
    inspect_path(path, true)
}

/// Reject an already occupied artifact name before a job starts.
pub(crate) fn require_absent_file(path: &Path) -> Result<()> {
    if inspect_file(path)? {
        return Err(CoreError::RestoreConflict {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

/// Write an artifact via an exclusive random staging file. New artifacts use
/// a no-clobber hard link; `replace` is reserved for an explicit update to an
/// existing record. As elsewhere, path inspection and replacement can race.
pub(crate) fn write_artifact(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    if replace {
        inspect_file(path)?;
    } else {
        require_absent_file(path)?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    inspect_directory(parent)?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent).map_err(|e| io_at(&parent.to_path_buf(), e))?;
    }
    inspect_directory(parent)?;
    let tmp = parent.join(format!(
        ".safereturn-{}.tmp",
        crate::hex::encode(&crate::crypto::random_array::<16>()?)
    ));
    let mut created = false;
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| io_at(&tmp, e))?;
        created = true;
        file.write_all(data).map_err(|e| io_at(&tmp, e))?;
        file.sync_all().map_err(|e| io_at(&tmp, e))?;
        drop(file);
        inspect_file(&tmp)?;
        if fs::read(&tmp).map_err(|e| io_at(&tmp, e))? != data {
            return Err(io_at(
                &tmp,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "staged artifact read-back did not match",
                ),
            ));
        }
        if replace {
            inspect_file(path)?;
            fs::rename(&tmp, path).map_err(|e| io_at(&path.to_path_buf(), e))?;
        } else {
            match fs::hard_link(&tmp, path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(CoreError::RestoreTargetChanged {
                        path: path.display().to_string(),
                    });
                }
                Err(e) => return Err(io_at(&path.to_path_buf(), e)),
            }
            fs::remove_file(&tmp).map_err(|e| io_at(&tmp, e))?;
        }
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_portable_path_escapes_and_windows_aliases() {
        for path in [
            "",
            "/absolute",
            "../escape",
            "root/../escape",
            "root//file",
            "root/./file",
            "root/file/",
            "C:/outside",
            "root\\file",
            "root/a:stream",
            "root/a?b",
            "root/trailing.",
            "root/trailing ",
            "root/CON.txt",
            "root/NUL .txt",
            "root/com1.log",
            "root/LPT².txt",
            "root/a\0b",
        ] {
            assert!(validate_relative_path(path).is_err(), "accepted {path:?}");
        }
        for path in [
            "root/file.txt",
            "root/空 文件.txt",
            "root/.hidden",
            "root/com10",
        ] {
            assert!(validate_relative_path(path).is_ok(), "rejected {path:?}");
        }
    }

    #[test]
    fn detects_duplicates_case_aliases_and_file_directory_conflicts() {
        for paths in [
            vec!["root/a", "root/a"],
            vec!["root/A", "root/a"],
            vec!["root/a", "root/A/child"],
            vec!["root/a/child", "root/a"],
        ] {
            assert!(validate_paths(paths).is_err());
        }
        assert!(validate_paths(["root/a", "root/b/child"]).is_ok());
    }
}
