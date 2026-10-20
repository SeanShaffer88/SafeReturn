//! SafeTarget checks (S6, slice 1): before any flow is allowed to
//! erase a disk, the candidate target is compared against the disks
//! it must never be — the disk the backup was captured from, the
//! disk holding the backup being restored, and the disk the
//! recovery media is running from — and against properties that make
//! an erase surprising (the running system's disk, a non-removable
//! internal disk).
//!
//! This module is pure: facts in, verdicts out, as data. The engine
//! enforces the verdicts in its guarded plan entry points
//! (`Engine::plan_system_restore_guarded`,
//! `Engine::plan_media_guarded`); the core planners accept an
//! assessment and refuse or demand an explicit, recorded override
//! (see `plan_system_restore_checked`, `plan_media_checked`).
//! Shells render the same verdicts so the user sees *why* a target
//! is refused or needs an extra confirmation — the shell never
//! re-decides.
//!
//! ## Identity, and why ambiguity refuses
//!
//! A disk is identified by the strongest facts available: serial
//! suffix + size + model together. The serial suffix is only the
//! last 4 characters of the serial (the privacy rule every
//! SafeReturn surface follows), and that is a **weak identifier**:
//! unrelated disks share a last-4 by chance, some USB bridges
//! report generic placeholder serials, and model strings for one
//! physical disk vary between enumeration APIs. So identity is a
//! three-way relation (`IdentityRelation`), never a boolean:
//!
//! - `Same` requires positive agreement: serial suffix equal, size
//!   equal, model equal (normalized) — all three known and matching.
//! - `Different` requires positive disagreement that cannot be an
//!   enumeration artifact: differing serial suffixes (serials are
//!   per-device), or differing sizes (a disk's size does not
//!   change) when the serial cannot be compared.
//! - Everything else is `Ambiguous`: partial facts, twin disks (same
//!   model and size, serial unknown), or contradictory facts (a
//!   matching disk id with a differing serial).
//!
//! For the three protected disks, `Ambiguous` refuses exactly like
//! `Same`. A false refusal costs the user a moment and a clearer
//! enumeration; a false allow can erase the only copy of their
//! backup. False refusals are acceptable; false allows are not.

use crate::media::MediaTargetFacts;
use crate::system_restore::SystemRestoreTargetFacts;
use safereturn_contract::DiskInfo;
use serde::{Deserialize, Serialize};

/// Strings-table id: target is the disk the backup was captured from.
pub const REASON_IS_SOURCE_DISK: &str = "target.is_source_disk";
/// Strings-table id: target is the disk holding the backup volume.
pub const REASON_IS_BACKUP_DISK: &str = "target.is_backup_disk";
/// Strings-table id: target is the disk the recovery media runs from.
pub const REASON_IS_MEDIA_DISK: &str = "target.is_media_disk";
/// Strings-table id: target might be a protected disk; the facts
/// cannot prove it is a different disk.
pub const REASON_IDENTITY_AMBIGUOUS: &str = "target.identity_ambiguous";
/// Strings-table id: target hosts a running operating system.
pub const WARNING_IS_SYSTEM_DISK: &str = "target.is_system_disk";
/// Strings-table id: target is a non-removable (internal/fixed) disk.
pub const WARNING_NON_REMOVABLE: &str = "target.non_removable";

/// The identity of a disk that must be protected from being chosen
/// as a target, as strongly as the caller can state it. Fields may
/// be empty/zero when a fact is unknown — the relation logic treats
/// them as unknown, never as matching.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskIdentity {
    /// Enumeration-scoped id (contract `DiskInfo.disk_id`). Useful
    /// corroboration within one enumeration; ids are NOT portable
    /// across enumerations, so a differing id alone never proves two
    /// entries are different disks.
    pub disk_id: String,
    pub model: String,
    /// Last 4 characters of the serial; empty when unknown.
    pub serial_suffix: String,
    /// 0 when unknown.
    pub size_bytes: u64,
}

impl DiskIdentity {
    pub fn of(disk_id: &str, model: &str, serial_suffix: &str, size_bytes: u64) -> Self {
        Self {
            disk_id: disk_id.to_string(),
            model: model.to_string(),
            serial_suffix: serial_suffix.to_string(),
            size_bytes,
        }
    }
}

/// Facts about a candidate target disk — the disk a flow proposes
/// to erase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetDiskFacts {
    pub disk_id: String,
    pub model: String,
    pub serial_suffix: String,
    pub size_bytes: u64,
    pub removable: bool,
    /// The disk hosts the operating system that is running now
    /// (in WinPE: the disk the media booted from is normally also
    /// the media disk; on a desktop, the disk Windows runs from).
    pub is_system_disk: bool,
}

impl TargetDiskFacts {
    pub fn identity(&self) -> DiskIdentity {
        DiskIdentity::of(
            &self.disk_id,
            &self.model,
            &self.serial_suffix,
            self.size_bytes,
        )
    }
}

impl From<&DiskInfo> for TargetDiskFacts {
    fn from(d: &DiskInfo) -> Self {
        Self {
            disk_id: d.disk_id.clone(),
            model: d.model.clone(),
            serial_suffix: d.serial_suffix.clone(),
            size_bytes: d.size_bytes,
            removable: d.is_removable,
            is_system_disk: d.is_system_disk,
        }
    }
}

impl From<&SystemRestoreTargetFacts> for TargetDiskFacts {
    /// The restore target facts do not record whether the disk is
    /// the running system's disk (in WinPE the restore flow runs
    /// from separate media; the shell that enumerated the disk knows
    /// and uses the guarded engine entry point with the flag it
    /// measured). From this conversion the flag is false; identity,
    /// size, and removability carry over exactly.
    fn from(t: &SystemRestoreTargetFacts) -> Self {
        Self {
            disk_id: t.disk_id.clone(),
            model: t.model.clone(),
            serial_suffix: t.serial_suffix.clone(),
            size_bytes: t.size_bytes,
            removable: t.removable,
            is_system_disk: false,
        }
    }
}

impl From<&MediaTargetFacts> for TargetDiskFacts {
    fn from(t: &MediaTargetFacts) -> Self {
        Self {
            disk_id: t.disk_id.clone(),
            model: t.model.clone(),
            serial_suffix: t.serial_suffix.clone(),
            size_bytes: t.size_bytes,
            removable: t.removable,
            is_system_disk: false,
        }
    }
}

/// The disks a target must be checked against, plus the warnings
/// the user has explicitly acknowledged in the plan flow. Supplied
/// by the shell (which enumerated the disks) or the CLI operator.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeTargetContext {
    /// The disk the backup set was captured from, when known.
    pub source_disk: Option<DiskIdentity>,
    /// The disk holding the backup volume in use, when known.
    pub backup_disk: Option<DiskIdentity>,
    /// The disk the running recovery media booted from, when known
    /// (the PE shell supplies this; desktop flows may not have one).
    pub media_disk: Option<DiskIdentity>,
    /// Warning ids (e.g. `target.non_removable`) the user has
    /// explicitly confirmed in the plan flow. An acknowledged
    /// warning is recorded in the resulting plan — never silent.
    pub acknowledged_warnings: Vec<String>,
}

impl SafeTargetContext {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn acknowledges(&self, warning_id: &str) -> bool {
        self.acknowledged_warnings.iter().any(|w| w == warning_id)
    }
}

/// How a candidate relates to one known disk. See the module docs
/// for why this is three-way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRelation {
    /// All comparable strong facts agree: same disk.
    Same,
    /// Facts disagree in a way that cannot be an artifact: a
    /// different disk.
    Different,
    /// The facts cannot prove either way. Treated as `Same` for
    /// protected disks — see the module docs.
    Ambiguous,
}

fn known_serial(s: &str) -> Option<&str> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Placeholder serials reported by some bridges/enclosures: one
    // repeated character ("0000", "AAAA") carries no identity.
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        if chars.all(|c| c == first) {
            return None;
        }
    }
    Some(s)
}

fn known_model(m: &str) -> Option<String> {
    let m = m.trim();
    if m.is_empty() {
        None
    } else {
        Some(m.to_lowercase())
    }
}

fn known_size(s: u64) -> Option<u64> {
    if s == 0 {
        None
    } else {
        Some(s)
    }
}

/// The identity relation between a candidate and one known disk.
/// Pure fact comparison; the rules (and their order) are the
/// contract documented at the top of this module.
pub fn identity_relation(candidate: &DiskIdentity, known: &DiskIdentity) -> IdentityRelation {
    let c_serial = known_serial(&candidate.serial_suffix);
    let k_serial = known_serial(&known.serial_suffix);
    let c_size = known_size(candidate.size_bytes);
    let k_size = known_size(known.size_bytes);
    let c_model = known_model(&candidate.model);
    let k_model = known_model(&known.model);

    let id_match = !candidate.disk_id.is_empty()
        && !known.disk_id.is_empty()
        && candidate.disk_id == known.disk_id;
    if id_match {
        // The enumeration says "same disk"; any strong fact that
        // contradicts it makes the identity ambiguous, never
        // silently different (the id may be stale) and never
        // silently the same disk either — the caller refuses.
        if (c_serial.is_some() && k_serial.is_some() && c_serial != k_serial)
            || (c_size.is_some() && k_size.is_some() && c_size != k_size)
            || (c_model.is_some() && k_model.is_some() && c_model != k_model)
        {
            return IdentityRelation::Ambiguous;
        }
        return IdentityRelation::Same;
    }

    if let (Some(cs), Some(ks)) = (c_serial, k_serial) {
        if cs != ks {
            // Serials are per-device; a differing suffix means a
            // differing serial, whatever the other facts say.
            return IdentityRelation::Different;
        }
        // Suffixes match — positive but weak evidence (last-4 only).
        if (c_size.is_some() && k_size.is_some() && c_size != k_size)
            || (c_model.is_some() && k_model.is_some() && c_model != k_model)
        {
            return IdentityRelation::Ambiguous;
        }
        if c_size.is_some() && k_size.is_some() && c_model.is_some() && k_model.is_some() {
            // Serial suffix + size + model all agree: the strongest
            // identification SafeReturn ever makes from these facts.
            return IdentityRelation::Same;
        }
        // A matching last-4 alone cannot confirm identity.
        return IdentityRelation::Ambiguous;
    }

    // The serial cannot be compared. A differing size still proves
    // a different disk — a disk's size does not change. Everything
    // else (twin disks of the same model and size, model-string
    // variance between enumerations, missing facts) is ambiguous.
    if c_size.is_some() && k_size.is_some() && c_size != k_size {
        return IdentityRelation::Different;
    }
    IdentityRelation::Ambiguous
}

/// One SafeTarget finding, as data. `Refuse` and `Warn` carry a
/// strings-table id the shell renders; the detail is the
/// engine-worded explanation (same role as warning `describe()`
/// text elsewhere in the core).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum SafeTargetVerdict {
    /// The target may be used (assessment-level summary; never
    /// appears inside an assessment's findings).
    Allow,
    Refuse {
        reason_id: String,
        detail: String,
    },
    Warn {
        warning_id: String,
        detail: String,
    },
}

/// The result of checking one candidate against one context: every
/// finding that applies, plus which warnings were acknowledged when
/// the check ran (copied from the context, so a plan built from
/// this assessment records exactly what was acknowledged).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafeTargetAssessment {
    pub findings: Vec<SafeTargetVerdict>,
    pub acknowledged_warnings: Vec<String>,
}

impl SafeTargetAssessment {
    /// No findings and no acknowledgments: the assessment of a flow
    /// that supplied no SafeTarget context at all. The planners
    /// treat this as "SafeTarget not applicable to this call" —
    /// it performs no checks and records nothing.
    pub fn no_context() -> Self {
        Self::default()
    }

    pub fn is_refused(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f, SafeTargetVerdict::Refuse { .. }))
    }

    /// The first refusal as (reason_id, detail).
    pub fn first_refusal(&self) -> Option<(&str, &str)> {
        self.findings.iter().find_map(|f| match f {
            SafeTargetVerdict::Refuse { reason_id, detail } => {
                Some((reason_id.as_str(), detail.as_str()))
            }
            _ => None,
        })
    }

    /// All warnings as (warning_id, detail), acknowledged or not.
    pub fn warnings(&self) -> Vec<(&str, &str)> {
        self.findings
            .iter()
            .filter_map(|f| match f {
                SafeTargetVerdict::Warn { warning_id, detail } => {
                    Some((warning_id.as_str(), detail.as_str()))
                }
                _ => None,
            })
            .collect()
    }

    /// Warnings the user has NOT acknowledged. A plan flow must
    /// refuse to proceed while any of these exist (the planners
    /// enforce this; shells render them for the explicit confirm).
    pub fn unacknowledged_warnings(&self) -> Vec<(&str, &str)> {
        self.warnings()
            .into_iter()
            .filter(|(id, _)| !self.acknowledged_warnings.iter().any(|a| a == id))
            .collect()
    }

    /// Warning ids that both fired and were acknowledged — what a
    /// plan records to prove the override was explicit.
    pub fn acknowledged_applied(&self) -> Vec<String> {
        self.warnings()
            .into_iter()
            .filter(|(id, _)| self.acknowledged_warnings.iter().any(|a| a == id))
            .map(|(id, _)| id.to_string())
            .collect()
    }

    /// The one-word summary: any refusal → Refuse; else any warning
    /// → the first Warn; else Allow.
    pub fn summary(&self) -> SafeTargetVerdict {
        if let Some(f) = self
            .findings
            .iter()
            .find(|f| matches!(f, SafeTargetVerdict::Refuse { .. }))
        {
            return f.clone();
        }
        if let Some(f) = self
            .findings
            .iter()
            .find(|f| matches!(f, SafeTargetVerdict::Warn { .. }))
        {
            return f.clone();
        }
        SafeTargetVerdict::Allow
    }
}

fn describe_identity(id: &DiskIdentity) -> String {
    let model = if id.model.trim().is_empty() {
        "unknown model"
    } else {
        id.model.trim()
    };
    let serial = known_serial(&id.serial_suffix)
        .map(|s| format!("serial …{s}"))
        .unwrap_or_else(|| "serial unknown".to_string());
    let size = known_size(id.size_bytes)
        .map(|s| format!("{s} bytes"))
        .unwrap_or_else(|| "size unknown".to_string());
    format!("{model} ({serial}, {size})")
}

/// Check a candidate target against a context. Findings are ordered
/// source → backup → media → system-disk → non-removable, so the
/// first refusal is always the most protective one.
pub fn check_target(
    candidate: &TargetDiskFacts,
    context: &SafeTargetContext,
) -> SafeTargetAssessment {
    let cand_id = candidate.identity();
    let mut findings = Vec::new();
    let protected: [(&str, &Option<DiskIdentity>, &str); 3] = [
        ("source disk", &context.source_disk, REASON_IS_SOURCE_DISK),
        ("backup disk", &context.backup_disk, REASON_IS_BACKUP_DISK),
        (
            "recovery media disk",
            &context.media_disk,
            REASON_IS_MEDIA_DISK,
        ),
    ];
    for (what, known, reason_id) in protected {
        let Some(known) = known else { continue };
        match identity_relation(&cand_id, known) {
            IdentityRelation::Same => findings.push(SafeTargetVerdict::Refuse {
                reason_id: reason_id.to_string(),
                detail: format!(
                    "the target is the {what} ({}) — erasing it would destroy the very thing this restore depends on",
                    describe_identity(known)
                ),
            }),
            IdentityRelation::Ambiguous => findings.push(SafeTargetVerdict::Refuse {
                reason_id: REASON_IDENTITY_AMBIGUOUS.to_string(),
                detail: format!(
                    "the target might be the {what} ({}): the available facts (model, size, last 4 of the serial) cannot prove it is a different disk. SafeReturn refuses rather than risk erasing it — a mistaken refusal can be corrected, an erased disk cannot",
                    describe_identity(known)
                ),
            }),
            IdentityRelation::Different => {}
        }
    }
    if candidate.is_system_disk {
        findings.push(SafeTargetVerdict::Warn {
            warning_id: WARNING_IS_SYSTEM_DISK.to_string(),
            detail: "the target disk hosts the operating system that is running now. Erasing it is only ever right in a guided recovery of a different PC's disk, never by accident".to_string(),
        });
    }
    if !candidate.removable {
        findings.push(SafeTargetVerdict::Warn {
            warning_id: WARNING_NON_REMOVABLE.to_string(),
            detail: "the target is a non-removable (internal or fixed) disk. Erasing it needs an explicit confirmation in the plan, and that confirmation is recorded in the plan".to_string(),
        });
    }
    SafeTargetAssessment {
        findings,
        acknowledged_warnings: context.acknowledged_warnings.clone(),
    }
}

/// Check a system-restore target (S5 facts + the system-disk flag
/// the enumerating shell measured).
pub fn assess_system_restore_target(
    target: &SystemRestoreTargetFacts,
    is_system_disk: bool,
    context: &SafeTargetContext,
) -> SafeTargetAssessment {
    let mut candidate = TargetDiskFacts::from(target);
    candidate.is_system_disk = is_system_disk;
    check_target(&candidate, context)
}

/// Check a media target (S4 facts + the system-disk flag the
/// enumerating shell measured).
pub fn assess_media_target(
    target: &MediaTargetFacts,
    is_system_disk: bool,
    context: &SafeTargetContext,
) -> SafeTargetAssessment {
    let mut candidate = TargetDiskFacts::from(target);
    candidate.is_system_disk = is_system_disk;
    check_target(&candidate, context)
}
