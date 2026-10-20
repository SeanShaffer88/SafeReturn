//! System facts for system backup sets (S3): what a whole-PC restore
//! needs to know about the machine a set came from — boot mode, Secure
//! Boot, BitLocker, the EFI System Partition's contents, WinRE, and
//! whether the BCD store was captured into the set.
//!
//! Honesty rules, enforced by the schema (not by convention):
//! - Every fact carries its **source** (where the value came from).
//! - A fact that could not be determined is an explicit *unknown*
//!   **with a reason** — `Fact::unknown`. There is no third state and
//!   no silent omission: `SystemFacts::validate` rejects an unknown
//!   without a reason, a known value that also carries an
//!   unknown-reason, and an empty source.
//! - The BCD store is either *included* (with the set path it was
//!   captured to) or *not included* (with a reason). Never ambiguous.
//!
//! Gathering real facts is Windows runtime work. This module provides
//! the schema, the gatherer interface, a static gatherer (facts
//! produced elsewhere — e.g. read from a file), an unavailable
//! gatherer (everything explicitly unknown), real ESP file listing,
//! and a Windows gatherer skeleton (cfg(windows), see its docs —
//! everything it cannot determine *by construction* is unknown with
//! the reason naming the runtime check that remains; the runtime
//! behavior is UNVERIFIED until the S0.5 on-machine session).

use crate::error::{io_at, CoreError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const SYSTEM_FACTS_FORMAT_VERSION: u32 = 1;

/// One fact, its provenance, and — when it could not be determined —
/// the reason why. See the module docs for the invariants `validate`
/// enforces on the pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fact<T> {
    /// The determined value; `None` means *unknown* (see
    /// `unknown_reason`, which is then required).
    pub value: Option<T>,
    /// Where this fact came from — an API, a command, a file, a
    /// gatherer. Never empty.
    pub source: String,
    /// Why the value is unknown. Required iff `value` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unknown_reason: Option<String>,
}

impl<T> Fact<T> {
    pub fn known(value: T, source: impl Into<String>) -> Self {
        Self {
            value: Some(value),
            source: source.into(),
            unknown_reason: None,
        }
    }

    pub fn unknown(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            value: None,
            source: source.into(),
            unknown_reason: Some(reason.into()),
        }
    }

    pub fn is_known(&self) -> bool {
        self.value.is_some()
    }

    fn validate(&self, what: &str) -> Result<()> {
        if self.source.trim().is_empty() {
            return Err(invalid(format!("{what}: fact has no source")));
        }
        match (&self.value, &self.unknown_reason) {
            (Some(_), None) => Ok(()),
            (None, Some(r)) if !r.trim().is_empty() => Ok(()),
            (Some(_), Some(_)) => Err(invalid(format!(
                "{what}: fact has both a value and an unknown-reason"
            ))),
            (None, _) => Err(invalid(format!(
                "{what}: fact is unknown but gives no reason"
            ))),
        }
    }
}

fn invalid(reason: String) -> CoreError {
    CoreError::InvalidSystemFacts { reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMode {
    Uefi,
    Bios,
}

/// BitLocker *protection* state for one volume, as a fact value.
/// Anything subtler (conversion in progress, key protectors) is for
/// the runtime gatherer to map — or to report as unknown with the
/// reason; the schema will not let it be guessed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BitLockerState {
    Off,
    On,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EspFile {
    /// Path inside the EFI System Partition, '/' separators.
    pub path: String,
    pub size: u64,
    /// SHA-256 of the file's content at capture time.
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinReInfo {
    pub present: bool,
    /// Where the Windows Recovery Environment was found (e.g. the
    /// Winre.wim path), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

/// Whether the BCD (Boot Configuration Data) store was captured into
/// the backup set. Included ⇒ `set_path` names where in the set;
/// not included ⇒ `not_included_reason` says why. Validation enforces
/// exactly one of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BcdCapture {
    pub included: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_path: Option<String>,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_included_reason: Option<String>,
}

impl BcdCapture {
    pub fn included(set_path: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            included: true,
            set_path: Some(set_path.into()),
            source: source.into(),
            not_included_reason: None,
        }
    }

    pub fn not_included(source: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            included: false,
            set_path: None,
            source: source.into(),
            not_included_reason: Some(reason.into()),
        }
    }

    fn validate(&self) -> Result<()> {
        if self.source.trim().is_empty() {
            return Err(invalid("bcd: capture has no source".to_string()));
        }
        match (self.included, &self.set_path, &self.not_included_reason) {
            (true, Some(p), None) if !p.trim().is_empty() => Ok(()),
            (false, None, Some(r)) if !r.trim().is_empty() => Ok(()),
            (true, _, _) => Err(invalid(
                "bcd: marked included but has no set path (or also gives a not-included reason)"
                    .to_string(),
            )),
            (false, _, _) => Err(invalid(
                "bcd: marked not included but gives no reason (or also gives a set path)"
                    .to_string(),
            )),
        }
    }
}

/// The system section of a set manifest. Facts only, each with its
/// source; unknowns are explicit and reasoned. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemFacts {
    pub format_version: u32,
    /// When these facts were gathered (unix seconds).
    pub gathered_unix: u64,
    pub boot_mode: Fact<BootMode>,
    pub secure_boot: Fact<bool>,
    /// BitLocker protection per volume, keyed by volume designator
    /// as the gatherer names it (e.g. "C:").
    pub bitlocker: BTreeMap<String, Fact<BitLockerState>>,
    /// Contents of the EFI System Partition (paths + hashes), when an
    /// ESP root was available to list.
    pub esp_files: Fact<Vec<EspFile>>,
    pub winre: Fact<WinReInfo>,
    pub bcd: BcdCapture,
}

impl SystemFacts {
    /// Enforce the honesty invariants: every fact has a source, every
    /// unknown has a reason, the BCD capture is unambiguous, and the
    /// format version is one this build understands.
    pub fn validate(&self) -> Result<()> {
        if self.format_version != SYSTEM_FACTS_FORMAT_VERSION {
            return Err(invalid(format!(
                "system facts format version {} is not supported by this build (expected {})",
                self.format_version, SYSTEM_FACTS_FORMAT_VERSION
            )));
        }
        self.boot_mode.validate("boot_mode")?;
        self.secure_boot.validate("secure_boot")?;
        for (volume, fact) in &self.bitlocker {
            fact.validate(&format!("bitlocker[{volume}]"))?;
        }
        self.esp_files.validate("esp_files")?;
        self.winre.validate("winre")?;
        self.bcd.validate()?;
        Ok(())
    }
}

/// A source of system facts. Real gathering is platform runtime work;
/// implementations must return unknowns-with-reasons for anything they
/// do not determine, never guesses.
pub trait SystemFactsGatherer {
    /// Gather facts now. `esp_root`, when supplied, is the mounted
    /// EFI System Partition root to list. `gathered_unix` is stamped
    /// onto the produced facts by gatherers that produce them fresh.
    fn gather(&self, esp_root: Option<&Path>, gathered_unix: u64) -> Result<SystemFacts>;
}

/// Facts produced elsewhere (e.g. by an on-machine gather run and
/// carried in a file): returns them as-is, after validation — an
/// invalid fact set is refused here rather than attached to a set.
#[derive(Debug, Clone)]
pub struct StaticFactsGatherer {
    facts: SystemFacts,
}

impl StaticFactsGatherer {
    pub fn new(facts: SystemFacts) -> Self {
        Self { facts }
    }
}

impl SystemFactsGatherer for StaticFactsGatherer {
    fn gather(&self, _esp_root: Option<&Path>, _gathered_unix: u64) -> Result<SystemFacts> {
        self.facts.validate()?;
        Ok(self.facts.clone())
    }
}

/// The gatherer for "we cannot gather here": every fact is unknown
/// with the same stated reason. This is what platforms without a real
/// gatherer use — the set still records *that* the facts are unknown
/// and why, instead of recording nothing.
#[derive(Debug, Clone)]
pub struct UnavailableGatherer {
    pub reason: String,
}

impl SystemFactsGatherer for UnavailableGatherer {
    fn gather(&self, _esp_root: Option<&Path>, gathered_unix: u64) -> Result<SystemFacts> {
        let source = "no system-facts gatherer available".to_string();
        let mut bitlocker = BTreeMap::new();
        bitlocker.insert(
            "C:".to_string(),
            Fact::unknown(source.clone(), self.reason.clone()),
        );
        Ok(SystemFacts {
            format_version: SYSTEM_FACTS_FORMAT_VERSION,
            gathered_unix,
            boot_mode: Fact::unknown(source.clone(), self.reason.clone()),
            secure_boot: Fact::unknown(source.clone(), self.reason.clone()),
            bitlocker,
            esp_files: Fact::unknown(source.clone(), self.reason.clone()),
            winre: Fact::unknown(source.clone(), self.reason.clone()),
            bcd: BcdCapture::not_included(source, self.reason.clone()),
        })
    }
}

/// List an EFI System Partition root: every regular file with its
/// size and SHA-256, paths relative with '/' separators, sorted.
/// Platform-independent (an ESP is a FAT tree once mounted); used by
/// gatherers and directly testable anywhere.
pub fn list_esp_files(esp_root: &Path) -> Result<Vec<EspFile>> {
    let mut files = Vec::new();
    let mut stack = vec![esp_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| io_at(&dir, e))? {
            let entry = entry.map_err(|e| io_at(&dir, e))?;
            let path = entry.path();
            let ftype = entry.file_type().map_err(|e| io_at(&path, e))?;
            if ftype.is_dir() {
                stack.push(path);
            } else if ftype.is_file() {
                let rel = path
                    .strip_prefix(esp_root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let mut reader = fs::File::open(&path).map_err(|e| io_at(&path, e))?;
                let mut hasher = sha2::Sha256::new();
                use sha2::Digest;
                let mut size = 0u64;
                let mut buf = [0u8; 64 * 1024];
                loop {
                    let n = reader.read(&mut buf).map_err(|e| io_at(&path, e))?;
                    if n == 0 {
                        break;
                    }
                    hasher.update(&buf[..n]);
                    size += n as u64;
                }
                files.push(EspFile {
                    path: rel,
                    size,
                    sha256: crate::hex::encode(&hasher.finalize()),
                });
            }
            // Non-regular ESP entries (there should be none on a FAT
            // system partition) are skipped by the walk; the listing is
            // a fact source for boot files, which are regular files.
        }
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(files)
}

/// The ESP fact for a supplied root, with provenance. A root that
/// cannot be listed becomes an explicit unknown with the reason —
/// gathering must not abort a backup over one fact.
pub fn esp_fact(esp_root: &Path, source: impl Into<String>) -> Fact<Vec<EspFile>> {
    let source = source.into();
    match list_esp_files(esp_root) {
        Ok(files) => Fact::known(files, source),
        Err(e) => Fact::unknown(source, format!("the ESP root could not be listed: {e}")),
    }
}

/// A facts file (as produced by an on-machine gather run) deserializes
/// into this; kept as a named constructor so the file format has one
/// obvious home.
pub fn parse_system_facts(json: &str) -> Result<SystemFacts> {
    let facts: SystemFacts = serde_json::from_str(json).map_err(|source| CoreError::Json {
        path: PathBuf::from("<system-facts>"),
        source,
    })?;
    facts.validate()?;
    Ok(facts)
}

#[cfg(windows)]
pub use windows_gatherer::WindowsFactsGatherer;

#[cfg(windows)]
mod windows_gatherer {
    //! Windows system-facts gatherer — SKELETON (S3).
    //!
    //! What is implemented is only what is determinable *by
    //! construction* from this code: the firmware type via the
    //! documented `GetFirmwareType` API (learn.microsoft.com:
    //! "GetFirmwareType function (winbase.h)") and WinRE presence at
    //! its default filesystem location. Everything that needs parsing
    //! command output (Secure Boot state, BitLocker status, BCD
    //! export) is returned as unknown with a reason naming the exact
    //! runtime check that remains — S0.5 on-machine work. No result
    //! here has been runtime-verified; see docs/S3_NOTES.md.

    use super::*;
    use std::path::PathBuf;

    extern "system" {
        fn GetFirmwareType(firmware_type: *mut u32) -> i32;
    }

    // FIRMWARE_TYPE values (winbase.h): Unknown=0, Bios=1, Uefi=2.
    fn boot_mode_fact() -> Fact<BootMode> {
        let source = "GetFirmwareType (Kernel32, winbase.h)".to_string();
        let mut firmware: u32 = 0;
        let ok = unsafe { GetFirmwareType(&mut firmware) };
        if ok == 0 {
            return Fact::unknown(source, "the GetFirmwareType call failed");
        }
        match firmware {
            1 => Fact::known(BootMode::Bios, source),
            2 => Fact::known(BootMode::Uefi, source),
            other => Fact::unknown(
                source,
                format!("the firmware reported an unrecognized type ({other})"),
            ),
        }
    }

    fn winre_fact() -> Fact<WinReInfo> {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".to_string());
        let dir = PathBuf::from(format!(r"{drive}\Windows\System32\Recovery"));
        let source = format!("filesystem check of {}", dir.display());
        let wim = dir.join("Winre.wim");
        if wim.is_file() {
            return Fact::known(
                WinReInfo {
                    present: true,
                    location: Some(wim.to_string_lossy().into_owned()),
                },
                source,
            );
        }
        Fact::unknown(
            source,
            "Winre.wim was not found at the default location; WinRE may live on a \
             separate recovery partition instead. Confirming with `reagentc /info` \
             is S0.5 runtime work — UNVERIFIED, not guessed here.",
        )
    }

    /// Skeleton gatherer: see the module docs for exactly what is and
    /// is not determined.
    #[derive(Debug, Default)]
    pub struct WindowsFactsGatherer;

    impl SystemFactsGatherer for WindowsFactsGatherer {
        fn gather(&self, esp_root: Option<&Path>, gathered_unix: u64) -> Result<SystemFacts> {
            let esp_files = match esp_root {
                Some(root) => esp_fact(root, "ESP root supplied to the gatherer"),
                None => Fact::unknown(
                    "no ESP root supplied",
                    "the EFI System Partition is not mounted at a fixed path; \
                     assign it a letter (mountvol / diskpart) and pass its root. \
                     Doing so at backup time is S0.5/S4 runtime work.",
                ),
            };
            let mut bitlocker = BTreeMap::new();
            bitlocker.insert(
                "C:".to_string(),
                Fact::unknown(
                    "not gathered by the skeleton gatherer",
                    "BitLocker status comes from `manage-bde -status` or the \
                     Win32_EncryptableVolume API; parsing/confirming either is \
                     S0.5 runtime work — UNVERIFIED, not guessed here.",
                ),
            );
            Ok(SystemFacts {
                format_version: SYSTEM_FACTS_FORMAT_VERSION,
                gathered_unix,
                boot_mode: boot_mode_fact(),
                secure_boot: Fact::unknown(
                    "not gathered by the skeleton gatherer",
                    "Secure Boot state lives in the UEFI variable mirrored at \
                     HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State \
                     (UEFISecureBootEnabled); reading and trusting it is S0.5 \
                     runtime work — UNVERIFIED, not guessed here.",
                ),
                bitlocker,
                esp_files,
                winre: winre_fact(),
                bcd: BcdCapture::not_included(
                    "not captured by the skeleton gatherer",
                    "capturing the BCD store (`bcdedit /export`) into the set is \
                     S0.5/S5 runtime work — UNVERIFIED, not attempted here.",
                ),
            })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn skeleton_gather_produces_valid_facts() {
            // Invariant only: whatever the skeleton can and cannot
            // determine on the CI runner, the produced facts must
            // satisfy the honesty schema (sources everywhere, reasons
            // for every unknown).
            let facts = WindowsFactsGatherer.gather(None, 1_700_000_000).unwrap();
            facts.validate().unwrap();
        }
    }
}
